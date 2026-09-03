# US-022 normalized mutation denominator — round 1 (branch `claude/us022-mutation-denominator`)

Recorded 2026-09-03 from tool output. Base: mainline `4a2b9c6`. Host: Linux
x86_64. Every exit code below was read from the process, not inferred.

This is a self-review of my own branch, not an independent review.

**The deliverable is a BLOCKED verdict.** `mutdenomctl -check` exits **1** with
**40 blocking findings** on the current tree, and it is supposed to. Neither
mutation engine is installed, no PIT run and no cargo-mutants run has ever
happened in this repository, and a green reading here would be the defect.

---

## Per-criterion census

AC1 verbatim: *"PIT and cargo-mutants run from promoted tool/dependency graphs
against the declared production and test surfaces and normalize killed,
survived, not-executed, uncovered, timeout, tool-failure, flaky, equivalent, and
technically-unviable dispositions into one signed denominator."*

**AC1 — NOT STARTED.** Read from the host, not assumed:

| thing AC1 requires | what is actually there |
| --- | --- |
| cargo-mutants runs | `cargo mutants --version` → **exit 101**. `command -v cargo-mutants` → **exit 1**. `~/.cargo/bin` holds cargo, cargo-clippy, cargo-fmt, cargo-miri, clippy-driver, rls, rust-analyzer, rust-gdb, rust-gdbgui, rust-lldb, rustc, rustdoc, rustfmt, rustup — and no cargo-mutants. |
| PIT runs | `mvn -o -q org.pitest:pitest-maven:help` → **exit 1**. `grep -rn "pitest\|org.pitest\|pit-maven"` over every `*.xml`, `*.json`, `*.go` and `Makefile` in the repository returns **zero hits**. `java-oracle/pom.xml` declares resources, compiler, surefire, antrun and jar plugins and no mutation plugin. |
| the pinned JDK PIT needs | `java -version` → **openjdk 21.0.10**. The promoted laboratory JDK is **17.0.19**. `.quarantine` is a symlink pointing at itself (`/home/user/verified-java-websocket-port/.quarantine -> /home/user/verified-java-websocket-port/.quarantine`) and resolves to nothing, so the Java-WebSocket 1.6.0 tree PIT would mutate is not reachable either. |
| promoted tool/dependency graphs | none exist for either engine. `rust/Cargo.toml` declares no cargo-mutants dev-dependency; `java-oracle/pom.xml` declares no PIT plugin. |
| the nine dispositions | the enum **already exists** in `assurance/schema/evidence-model-1.1.0.schema.json` (`MutationResultRecord.disposition`, `source_tool` ∈ {PIT, cargo-mutants}) and **nothing in the repository ever produced a record under it**. Not one killed/survived/not_executed/uncovered/timeout/tool_failure/flaky/equivalent/technically_unviable row exists. |
| one signed denominator | no denominator existed before this branch. No signing key is in the repository; `internal/intake/sign.go` takes the Ed25519 private key as an argument from the protected operator. `corpora/{hidden,sealed}/manifest.json` both record `"signing": false`. |
| `evidence/mutation` | **does not exist.** |

**AC2 — NOT ASSESSABLE, and one live finding.** An eligible mutation score is a
ratio over a population; with no population there is no ratio. The one thing
here that *is* assessable is the equivalence gate, and it fails today: the four
`EQUIVALENT_DOCUMENTED` entries in `mutants/e1-ws-core-manifest.json`
(`m016-1005-reason-flip`, `m016-range-lower-off-by-one`,
`m016-send-close-normalize-skip`, `mprobe-step-counter-fatal-drop`) carry
genuinely strong technical evidence — exhaustive in-test witnesses, not
hand-waving — and **zero independent explicit review**. `mutants/manifest.json`
records `independent_review_claimed: false`. Under AC2 all four would block.

**AC3 — NOT RUN, and nothing on this branch violates it.** AC3's four
reconciliation runs (no-stub before/after, test-manifest before/after) have no
"before" and no "after" because there is no campaign between them. All four are
recorded `NOT_RUN` with `exit: -998` (the repo's sentinel for *no ProcessState
existed*; it is not an exit code) rather than fabricated. Separately: this
branch **adds** `internal/mutdenom`, `cmd/mutdenomctl` and
`assurance/mutation/` and **modifies no pre-existing file** — no test deleted,
weakened, skipped, filtered or replaced.

**AC4 — NOT SATISFIED, and the check found a real defect in what exists.** No
mutation campaign ran on either protected arm, so AC4's separation cannot be
satisfied. But AC4's separation requirements are stated as checkable structure
(below), and reading the two witnesses that *do* exist in the repository turned
up this:

- `corpora/hidden/manifest.json` and `corpora/sealed/manifest.json` declare the
  **same** `generator.secret_seed_commitment`
  (`sha256:08ae5e87916ad20c76dd4d7450e23a87cb966ad4e8ed58be4dffd8430173f331`).
  Two tiers seeded from one secret are one credential wearing two names. The
  checker raises `MUT_ARM_SEPARATION_SHARED` on this, from a real read of both
  files, not from a fixture.
- They also declare the same `custodian.policy_digest`
  (`sha256:67b20f39…`) and the same
  `execution_evidence.report_sha256` (`sha256:61e1ce89…`). Only the transcript
  digests differ. Whatever that shared report is, it is one artifact covering
  both tiers.

I am **not** claiming this is an AC4 verdict on US-005's corpora — those
manifests are corpus evidence for a different story and were never asked to
satisfy AC4. I am recording that the only per-tier separation witnesses the
repository holds today are identical on the dimension AC4 cares most about, and
that a US-022 protected evaluation cannot inherit them.

**AC5 — NOT RUN, all six legs.** Real, related evidence exists for four of the
six clauses and belongs to **US-005**, not here: pristine Java 74/74 on the
public tier, the inert `rust/candidate-stub` at 74 failed, and both planted Java
mutants killed. None of it is the AC5 leg of a mutation campaign, because there
was no mutation campaign. The sixth leg — zero protected leakage — is the one I
want to be loudest about: **absence of leakage from a run that did not happen is
not a pass**, and recording it as one would be the exact dishonesty this story
exists to prevent.

### Two substitutions I refused

- **A corpus manifest is not a protected evaluation.**
  `corpora/hidden/manifest.json` and `corpora/sealed/manifest.json` record 92
  executed behaviour scenarios per tier, a commitment root, and a transcript
  digest. They record no mutant, no engine, no disposition, and no separation of
  identity, cache, credential, signing key or workspace. They are cited in the
  denominator **only** as the AC4 witnesses the check reads.
- **An AC5 mutant catalogue is not a normalized mutation denominator.**
  `mutants/e1-ws-core-manifest.json` holds 76 hand-curated exact-literal
  substitutions at named ws-core sites (72 `KILLED_BY_TESTS`, 4
  `EQUIVALENT_DOCUMENTED`). Good evidence for US-012–US-016 AC5, and not this.
  Its 76 mutants were **chosen**, not enumerated by cargo-mutants over
  `rust/ws-core/src`, so the mutants nobody wrote down were never counted and the
  set has no denominator relationship to the surface. Its vocabulary is five
  verdicts, not AC1's nine dispositions: it has no `not_executed`, no
  `uncovered`, no `timeout`, no `flaky`, and no `technically_unviable` class at
  all. It is deliberately **not carried in the denominator as a population**,
  because carrying it would be the substitution.

  `mutdenomctl -normalize-e1` reads that file from disk and prints the nine-class
  normalization of all 76 entries, so the refusal is a reading rather than an
  opinion:

  ```
  gate=mutdenom step=normalize total=76 equivalent=4 killed=72
  ```

  every equivalent row printing `evidence=present review=absent`. The
  normalization map is exported (`NormalizeCuratedVerdict`) so it can be argued
  with. The one judgement call in it: **`BUILD_FAILED` normalizes to
  `tool_failure`, not `technically_unviable`.** "The harness could not build it"
  is a statement about the run, not about the mutant, and filing it as
  technically-unviable would move a mutant out of the eligible set on the
  strength of a build error — exactly the reclassification AC2's
  evidence-and-review gate exists to stop.

  One further trap worth naming because it looks like coverage: the 76 mutants
  are **all** in `rust/ws-core/src`. Not one mutant of `rust/ws-driver/src`
  exists anywhere in the repository, curated or enumerated.

---

## What I built

- `assurance/mutation/denominator.json` — the denominator, as a checked artifact.
- `internal/mutdenom/` — the checker, as production code (the repo's own lesson
  from the ledger gate: a rule that lives only in a `_test.go` is run by no
  release path).
- `cmd/mutdenomctl/` — `-check`, `-replay-fixtures`, `-emit-digest`,
  `-emit-payload-digest`, `-normalize-e1`, `-sign-fixture`.
- `assurance/mutation/fixtures/` — 80 polarity cases, exactly one green.
- `assurance/mutation/tools/` — the generators and the deletion attack, with a
  README stating what each is and what it edits. None of them is evidence.

### The denominator, and what makes it un-gameable

The nine AC1 classes are taken verbatim and are identical to the
`MutationResultRecord.disposition` enum already frozen in
`assurance/schema/evidence-model-1.1.0.schema.json`, so this is the repository's
own vocabulary rather than a new one. The rules that make the count mean
something:

1. **Every mutant lands in exactly one class.** A record with no disposition
   raises `MUT_DISPOSITION_ABSENT`; a tenth class raises
   `MUT_DISPOSITION_UNKNOWN` (on a record) or
   `MUT_CLASS_TABLE_DISPOSITION_UNKNOWN` (in the class table — two codes, so a
   deletion of either cannot hide behind the other).
2. **A mutant cannot be silently absent.** `len(records) == declared_total`, the
   class table sums to `declared_total`, *and* the class table equals the
   per-record tally — three separate rules with three separate codes, because
   the class table can agree with the total while disagreeing with the records.
   Where a population is normalized from an on-disk campaign manifest, its size
   is **re-derived from that file** (`MUT_SOURCE_MANIFEST_COUNT_DRIFT`).
   Duplicate mutant ids raise `MUT_MUTANT_ID_DUPLICATE`: one mutant counted twice
   inflates every denominator it is in.
3. **Nothing leaves the denominator.** Any record with `in_denominator: false`
   blocks, whatever its class.
4. **Only two classes may leave the ELIGIBLE set, and only with both gates.**
   `equivalent` and `technically_unviable` require technical evidence
   (`MUT_EQUIVALENCE_EVIDENCE_ABSENT`) **and** an independent explicit review
   (`MUT_EQUIVALENCE_REVIEW_ABSENT`), where the review must exist as a record
   (`MUT_REVIEW_RECORD_MISSING`), carry role `independent-reviewer`
   (`MUT_REVIEW_NOT_INDEPENDENT`), be blind (`MUT_REVIEW_NOT_BLIND` — the master
   story says **dual-blind**), and be an APPROVE (`MUT_REVIEW_NOT_APPROVED`).
   The review itself is an owner action I cannot perform; what I can do, and did,
   is make its absence a typed BLOCK rather than a footnote. Mislabelling
   eligibility in either direction raises `MUT_ELIGIBILITY_MISLABELLED`.
5. **The score is recomputed, never read.** `denominator_total`,
   `eligible_total`, `killed_total`, `missed_total` and
   `eligible_score_percent` are each recomputed from the records and compared,
   each with its own drift code. `survived`, `not_executed`, `uncovered`,
   `timeout`, `tool_failure` and `flaky` all count as MISSED — none of them is a
   demonstration that a test caught anything — and any MISSED raises
   `MUT_MISSED_NONZERO`.
6. **A ratio over a fragment is not a score.** If any population is
   unenumerated, `MUT_SCORE_NOT_COMPUTABLE` blocks. This is the rule that stops
   the current tree's "0 missed out of 0 eligible" from ever being read as 100%.
7. **The surfaces are re-derived.** Every declared production and test surface is
   digest-re-checked against the tree under `CANONICAL_PATH_SHA256_V1` (the
   scheme `assurance/replay/fixtures/us006-cases.json` and
   `assurance/fuzz/manifest.json` already use), with digest and file-count drift
   as separate codes. A declared production surface with no population raises
   `MUT_SURFACE_HAS_NO_POPULATION`: a surface nobody enumerated is a surface
   nobody mutated.
8. **The signature covers the document, not a summary.**
   `MUTDENOM_PAYLOAD_SHA256_V1` is sha256 over the whole manifest with exactly
   two fields blanked — `signature.signature` and `signature.payload_digest`.
   Every surface, population, record, review, arm, leg, key id and claim is
   inside it. A unit test proves this both ways: mutating either excluded field
   leaves the digest still, and mutating any of twelve other fields moves it.
9. **The document cannot grade itself.** Any `ac*_met: true` while a BLOCK stands
   raises `UNAVAILABLE_REPRESENTED_AS_SUCCESS`.

### Unavailable tooling blocks, in both directions

Following `internal/fuzzpin`, `internal/formalplan`'s
`UNAVAILABLE_REPRESENTED_AS_SKIP` / `UNAVAILABLE_BACKEND_CLAIM`, and the ledger
gate's refusal when `VJWP_PROTECTED_STORE` is unreachable:

- a failed engine probe raises `MUT_ENGINE_UNAVAILABLE` (**BLOCK**),
  unconditionally, with the exit code read from the real `ProcessState` and
  printed verbatim;
- a population recorded `ENUMERATED`, or an arm recorded `RUN`, on an engine that
  probed unavailable raises `UNAVAILABLE_REPRESENTED_AS_SKIP` (**BLOCK**) —
  claiming a campaign on an absent engine is its own finding;
- **the inverse evasion**: a population parked
  `NOT_ENUMERATED_ENGINE_UNAVAILABLE`, or an arm parked
  `NOT_RUN_ENGINE_UNAVAILABLE`, while the engine probes **available** raises the
  same finding. Parking work as blocked-on-tooling while the tool is right there
  hides a campaign nobody ran;
- **there is no `SKIPPED` status.** Writing one raises
  `MUT_STATUS_SKIPPED_FORBIDDEN` (**BLOCK**) — refused *by name*, so it cannot
  fall through to a generic "unknown status";
- the toolchain under the engine is probed too:
  `MUT_TOOLCHAIN_VERSION_MISMATCH` fires today because the pinned OpenJDK
  17.0.19 is gone and only 21.0.10 is present. A campaign on the wrong runtime
  is a campaign about a different program;
- AC1's "promoted tool/dependency graphs" is a precondition, not a preamble:
  `MUT_DEPENDENCY_GRAPH_NOT_PROMOTED` blocks, and a graph declared PROMOTED with
  no record, or with a record that is not on disk, raises
  `MUT_PROMOTION_RECORD_ABSENT` — promotion that names no record is an adjective.

The load-bearing fixture is `engine-unavailable-honestly-blocked`: the engine is
genuinely absent, the manifest says so **honestly**, the population is parked and
the arms are parked — and it still BLOCKS. Missing tooling is a block, never a
pass.

### AC4's requirements as checkable structure

I cannot execute a hidden or sealed run and I claim none. What the denominator
does instead is state, per arm and per dimension, **what would have to be true
and what the check would read** — and the checker prints that sentence in the
finding when the dimension is undeclared, so it is in the tool's output rather
than only in prose.

| AC4 dimension | what would have to be true | what the check reads today | verdict |
| --- | --- | --- | --- |
| identity | a custodian identity distinct per tier, bound to the run | nothing. The only custodian field is `custodian.policy_digest`, which is a policy, not an identity, and is byte-identical across tiers | `MUT_ARM_SEPARATION_DIMENSION_MISSING` |
| filesystem | separate roots the other arm cannot reach | `corpora/{hidden,sealed}/manifest.json#artifacts.0.path` — `us005-corpora/hidden/…` vs `…/sealed/…`, genuinely distinct | **passes**, and it is the weakest of the six: a distinct path is not a distinct filesystem |
| cache | a build/tool cache root used by one arm and nothing else, outside the public workspace | nothing; no per-tier cache is recorded anywhere | `MUT_ARM_SEPARATION_DIMENSION_MISSING` |
| credential | distinct secret material per tier | `…#generator.secret_seed_commitment` — **identical across tiers** | `MUT_ARM_SEPARATION_SHARED` |
| signing key | distinct keys, so a hidden receipt cannot be minted by whoever holds the sealed key | nothing; both manifests record `"signing": false`, so there is no key to be separate | `MUT_ARM_SEPARATION_DIMENSION_MISSING` |
| workspace | a checkout each arm owns exclusively, neither a parent nor a child of the other, resolved via `EvalSymlinks` and path-component comparison rather than a string prefix | nothing | `MUT_ARM_SEPARATION_DIMENSION_MISSING` |

Plus AC4's four non-separation clauses, each its own code and each blocking
today: `MUT_ARM_NETWORK_DENIAL_UNDECLARED`,
`MUT_ARM_PROTECTED_STORE_DENIAL_UNDECLARED`, `MUT_ARM_BUDGET_NOT_MONOTONIC`,
`MUT_ARM_DIAGNOSTIC_POLICY_ABSENT`. An arm AC4 names by name that is absent
altogether raises `MUT_ARM_MISSING`.

**None of this is a claim that AC4 is satisfied. Every row above is either a
BLOCK or a single weak witness.**

---

## `-check` output: the blocking reasons, by name

`go run ./cmd/mutdenomctl -check -root .` → **exit 1**, state BLOCKED,
**40 blocking findings**:

```
gate=mutdenom step=engine-probe engine=cargo-mutants command="cargo mutants --version" exit=101 available=false
gate=mutdenom step=engine-probe engine=pit command="mvn -o -q org.pitest:pitest-maven:help" exit=1 available=false
```

| finding | count | why |
| --- | --- | --- |
| `MUT_ENGINE_UNAVAILABLE` | 2 | cargo-mutants exit 101, PIT exit 1 |
| `MUT_DEPENDENCY_GRAPH_NOT_PROMOTED` | 2 | neither engine has a promoted graph |
| `MUT_TOOLCHAIN_VERSION_MISMATCH` | 1 | pinned OpenJDK 17.0.19 absent; observed `openjdk version "21.0.10"` |
| `MUT_POPULATION_NOT_ENUMERATED` | 3 | ws-core, ws-driver, java-oracle: no population exists |
| `MUT_SCORE_NOT_COMPUTABLE` | 1 | the eligible mutation score of the declared surfaces cannot be computed |
| `MUT_ARM_NOT_RUN` | 2 | hidden, sealed |
| `MUT_ARM_SEPARATION_DIMENSION_MISSING` | 8 | identity, cache, signing_key, workspace × 2 arms |
| `MUT_ARM_SEPARATION_SHARED` | 1 | hidden and sealed share one credential commitment |
| `MUT_ARM_NETWORK_DENIAL_UNDECLARED` | 2 | |
| `MUT_ARM_PROTECTED_STORE_DENIAL_UNDECLARED` | 2 | |
| `MUT_ARM_BUDGET_NOT_MONOTONIC` | 2 | |
| `MUT_ARM_DIAGNOSTIC_POLICY_ABSENT` | 2 | |
| `MUT_RECONCILIATION_LEG_NOT_RUN` | 4 | AC3's before/after legs have no campaign between them |
| `MUT_AC5_LEG_NOT_PASSED` | 6 | all six AC5 clauses |
| `MUT_SIGNATURE_ABSENT` | 1 | AC1 requires one **signed** denominator |
| `MUT_SIGNING_KEY_ABSENT` | 1 | the Ed25519 key is the protected operator's |

---

## RED readings and deletion attacks

**Polarity suite.** `assurance/mutation/fixtures/cases.json` — 80 cases through
the **real** checker, each pinning an exact exit code, state and set of typed
BLOCK codes. **Exactly one case is green**, so a checker that blocked
unconditionally would fail its own suite; the runner refuses a catalog with no
green case for precisely that reason. Every other case is a **single** mutation
of the green base, so the rule it targets is the reason it is red.

`go run ./cmd/mutdenomctl -replay-fixtures … -root .` → **exit 0**, 80 cases,
1 green, **0 failures**.

Four of those cases attack the signature block *after* signing, because a
mutation applied before signing would simply be re-stamped by the signer:
`payload-digest-drift`, `signature-does-not-verify` (a signature of the right
shape over the wrong thing — present-but-unverifiable raises the same BLOCK as
absent, because it *looks* signed), `signature-key-unusable`, and
`signing-key-absent`.

**Deletion attack.** Every BLOCK `add(...)` call site in
`internal/mutdenom/check.go` neutered one at a time, each required to turn the
suite red. Script committed at `assurance/mutation/tools/attack.py`; transcripts at
`…/scratchpad/attack.txt` (pass 1) and `attack2.txt` (pass 2).

**First pass: 80 mutations, 4 survivors** — and they are the most useful thing in
this record, because each one is a check that was decoration until this pass.

| survivor | why it stayed green | fix |
| --- | --- | --- |
| `MUT_TOOLCHAIN_VERSION_MISMATCH`, the *probe-failed* branch | every fixture's toolchain probe ran successfully, so only the version-mismatch branch was ever witnessed | new fixture `toolchain-probe-unrunnable`: the probe binary does not exist, so the pinned runtime cannot be **observed at all**. Not being able to decide the runtime is not deciding it is right |
| `MUT_SCORE_NOT_COMPUTABLE`, the *honestly-declared-incomputable* branch | every fixture with an unenumerated population still declared `computable: true`, so the honest branch had no witness | new fixture `score-honestly-not-computable`, which is **the shipped artifact's own shape**: engine absent, population honestly parked, arms honestly parked, score honestly zero and honestly not computable — and still BLOCKED |
| `MUT_PAYLOAD_DIGEST_DRIFT`, the *digest-not-computable* branch | `json.Marshal` of this struct cannot fail, so no manifest can ever reach it | **removed**. A branch no fixture can reach is not a check; it is unfalsifiable code that makes the suite look bigger than it is. An error now leaves the digest empty, which never equals a declared digest, so the single remaining comparison still fires |
| `MUT_SIGNING_KEY_ABSENT`, the *key-present-but-unusable* branch | **masking**: it shared a code with the key-absent branch, and the only fixture for it cleared the key, so both fired and deleting either left the other holding the code | split into `MUT_SIGNATURE_KEY_UNUSABLE` with its own fixture (`signature-key-unusable`, a non-hex key alongside a real signature) |

That fourth one is the same defect US-021's attack found twice — a check whose
only witness is another check's finding. It is apparently the standing failure
mode of this kind of tool, and it is invisible without deleting the checks.

**Second pass: 79 mutations, 0 survivors, attack exit 0**, and
`check.go` restored **byte-identical** (verified, not assumed — the script
compares the restored file against the pristine text it started from). 79 rather
than 80 because the unreachable digest branch was removed rather than given a
fixture it could never have.

Four of my checks were decorative until this pass. I would not have found any of
them without deleting the checks; the polarity suite was green over all four.

**A mutation that breaks compilation proves nothing**, so no code was deleted:
each BLOCK `add(...)` call was wrapped in `if false { … }`, which still compiles
and still type-checks. The file was restored from a backup in a `finally` block
and the restoration was verified byte-identical.

---

## Exit codes read from the process

| command | exit |
| --- | --- |
| `go run ./cmd/mutdenomctl -check -root .` | **1** (BLOCKED, 40 blocking findings) — *by design* |
| `go run ./cmd/mutdenomctl -replay-fixtures assurance/mutation/fixtures/cases.json -root .` | **0** (80 cases, 1 green, 0 failures) |
| `go run ./cmd/mutdenomctl -normalize-e1 -root .` | **0** (76 entries: 72 killed, 4 equivalent, 0 unmapped) |
| deletion attack, pass 1 (80 mutations) | **1** (4 survivors) |
| deletion attack, pass 2 (79 mutations) | **0** (0 survivors, restore byte-identical) |
| `go build ./...` | **0** |
| `go vet ./internal/mutdenom/ ./cmd/mutdenomctl/` | **0** |
| `gofmt -l internal/mutdenom cmd/mutdenomctl` | **0** (no output) |
| `go test ./internal/mutdenom/ -count=1` | **0** (7 tests, 8.283s) |
| `go run ./cmd/deltaledgerctl --root . --check` (with `VJWP_PROTECTED_STORE` set) | **0** |
| `cargo mutants --version` | **101** — the block |
| `command -v cargo-mutants` | **1** |
| `mvn -o -q org.pitest:pitest-maven:help` | **1** — the block |
| `java -version` | **0**, output `openjdk version "21.0.10"` — the toolchain block |
| `cargo --version` | **0**, output `cargo 1.95.0 (f2d3ce0bd 2026-03-21)` |

`git diff --name-only 4a2b9c6 --diff-filter=MD` is **empty**: this branch modifies
and deletes nothing that existed on mainline.

## The full Go suite, and two failures that are not baseline-listed

`VJWP_PROTECTED_STORE=… go test ./... -timeout 40m -count=1` exited **1**. Five
packages failed. Three are the declared baseline (`internal/formalplan`,
`internal/lab`, `internal/portplan`). `internal/mutdenom` is **ok, 14.433s**.

The other two — `cmd/formalcoverctl` (3 tests) and `internal/formalcoverage` —
were **not** on the given baseline list, so I did not assume they were
pre-existing. "It can't be mine" is an argument, not a reading. I extracted a
pristine mainline tree (`git archive 4a2b9c6 | tar -x`) and ran both packages
there:

```
cmd/formalcoverctl        FAIL 0.036s   (pristine 4a2b9c6)
internal/formalcoverage   FAIL 0.684s   (pristine 4a2b9c6)
```

Byte-identical failure, same tests, same message in both:

> `websocket_driver::ConnectionOwner::poll/NEAREST_DECLARATION_IS_AT_THE_LINE_IT_CITES:`
> `rust/ws-driver/src/lib.rs:756` reads `"/// Result of one bounded owner transition."`,
> the record says `"pub fn poll<'owner>(&'owner mut self, …"`

So: **pre-existing on mainline `4a2b9c6`, and not on the baseline list.** The
plane-correspondence record cites a line that has drifted from the declaration it
names. This branch cannot have caused it —
`git diff --name-only 4a2b9c6 HEAD -- rust assurance/formal evidence` is empty,
and those three trees are the only inputs the failing check reads — but the
failure is real and the baseline list should either grow to include it or it
should be fixed. That is somebody else's story; I am recording it, not
adjudicating it.

---

## Claim grade

**observed**, and it describes only what this document *is*: an executed census —
engine probes run and their exit codes read, surface digests re-derived,
separation witnesses read out of the files that hold them, and a checker whose
own rules are proven falsifiable. It is **not** a mutation campaign at any grade,
because no mutation campaign exists. A census is not a campaign, and a plan is
not evidence.

---

## What I did NOT do, by name

- I did **not** install cargo-mutants, PIT, or the pinned OpenJDK 17.0.19, and I
  did not repair `.quarantine`. All four are out of scope, all four would change
  the pinned toolchain or the quarantine boundary the whole project depends on,
  and the correct response to absent tooling here is to block — which is what I
  built.
- I did **not** run any mutation campaign, on any surface, in any arm. There are
  zero PIT runs and zero cargo-mutants runs on this branch, exactly as there were
  before it.
- I did **not** carry `mutants/e1-ws-core-manifest.json`'s 76 curated mutants
  into the denominator as a population. Recording the gap and importing a
  catalogue that does not answer AC1 are different jobs, and the second would be
  the substitution.
- I did **not** perform the independent explicit review AC2 requires for the four
  existing `EQUIVALENT_DOCUMENTED` classifications. It is an owner action, and a
  self-review of my own branch cannot be it. I modelled the requirement so its
  absence blocks; I did not satisfy it.
- I did **not** attempt a hidden or sealed run, and I make no AC4 claim of any
  kind. Every AC4 dimension is a BLOCK or a single weak witness.
- I did **not** sign the denominator. The Ed25519 key material is the protected
  operator's; `internal/intake/sign.go` takes it as an argument and this
  repository stores no private key. The published fixture key in
  `cmd/mutdenomctl/fixture_key.go` exists only so the polarity suite can have a
  genuinely verifying green case, and `-sign-fixture` **refuses** any document
  whose id does not begin with `us022-polarity-fixture-` — signing the real
  denominator with a published key would be worse than leaving it unsigned,
  because it would look signed.
- I did **not** decide which Java tree PIT's declared production surface is. AC1
  says "the declared production surface", and no record in this repository
  declares whether that is `java-oracle/src/main/java` (the retained adapter) or
  Java-WebSocket 1.6.0 in `.quarantine` (the code actually under port). The
  denominator names the open question in the surface's own note; the decision
  belongs to whoever schedules US-022, and in the delta ledger, not here.
- I did **not** wire `mutdenomctl` into `make -C rust gates`. It exits 1 by
  design on the current tree, so wiring it in would turn every sibling branch red
  for a gap none of them introduced. Following US-021's precedent exactly: **the
  owner should wire it at the point US-022 is scheduled to close**, at which
  point its exit code becomes the story's answer.
- I did **not** run Autobahn, any benchmark, or anything touching AWS.
- I did **not** modify `evidence/java/behavior-delta-ledger.json`,
  `internal/deltaledger`, `assurance/concurrency/results.json`,
  `internal/normcollide`, or any existing mutant in `cmd/mutctl`.
- I did **not** weaken, delete, skip or filter any existing test. This branch
  adds files and modifies none; the deletion attack mutated only my own
  `internal/mutdenom/check.go` and restored it byte-identically.
- I did **not** verify that `corpora/{hidden,sealed}`'s shared seed commitment,
  shared policy digest and shared report digest are defects **in US-005's own
  terms**. They may be intended there. What I verified is that they are the only
  per-tier separation witnesses this repository holds, and that US-022's AC4
  cannot inherit them.

---

## Exact owner actions this leaves

1. Decide PIT's declared Java production surface (adapter vs. quarantined
   Java-WebSocket 1.6.0) and record it in the delta ledger.
2. Promote a cargo-mutants dependency graph and a PIT plugin graph, or record
   why neither can be promoted — either way the block stays until one of those
   two things happens.
3. Restore the pinned OpenJDK 17.0.19 and the `.quarantine` tree before any PIT
   run is meaningful.
4. Commission the dual-blind independent review of the four existing
   `EQUIVALENT_DOCUMENTED` classifications, and of any future `equivalent` or
   `technically_unviable` disposition. The denominator carries the review record
   shape; it needs a reviewer who is not me.
5. Sign the denominator with the protected operator's Ed25519 key once a real
   population exists. Signing it now would be signing a draft.
6. Wire `go run ./cmd/mutdenomctl -check -root .` into the gates at the point
   US-022 is scheduled to close.
