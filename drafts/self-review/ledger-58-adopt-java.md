# Ledger sequence 58 becomes `adopt-java` — by supersession, and the two consumers the append knocked over

Branch `claude/ledger-58-adopt-java`, worktree `/home/user/vjwp-ledger58`,
based on `origin/claude/feature/verified-java-websocket-port` at `6a155a3`.
Every exit code below was READ FROM THE PROCESS that produced it, never
inferred from the text it printed. No Autobahn run, no live Java process, no
AWS run and no benchmark run was made. **No port byte changed** — this landing
touches the ledger, its downstream bindings, and three records.

Mainline moved by one commit while this ran (`8218815`, which removes the
tracked `.quarantine` symlink that `6a155a3` still carries). This branch is
based where the task said, on `6a155a3`; the divergence is noted in §7.

---

## 1. What the owner ruled, and what that costs the tree

Two rulings, both authorized:

- **F010**: the 2026-08-27 amendment's *"every AC clause"* DOES reach US-011
  AC2's banner clause. DIV-06 emitting `Date` and
  `Server: TooTallNate Java-WebSocket` is **compliance, not violation**.
- **Ledger sequence 58**: its disposition becomes **`adopt-java`**, with
  `mismatch_class` staying **`underspecified-behavior`**.

The ledger is append-only with a **frozen prefix through sequence 35**, and the
standing ruling `protected/ledger-frozen-prefix-owner-decision-2026-08-28.json`
(sha256 `bb3cd0da…`) is **SUPERSEDE, DO NOT REWRITE**. A disposition is not a
typo to be corrected in place. So the ruling is recorded as a new record
appended beside the one it corrects, and sequence 58 keeps its bytes and its
digest — the question and its answer stand next to each other.

| what | value |
| --- | --- |
| new sequence | **59** |
| delta id | `delta-19de2302e80753564b622f718692411fd251a704bcd0f6c739d93f1e4d5612ca` |
| subject | `semantic:org.java-websocket.draft6455.server-handshake.response-server-and-date-fields.adopted:provisional-v1` |
| disposition | **`adopt-java`** |
| mismatch class | **`underspecified-behavior`** |
| supersedes | sequence 58, `delta-b0350fc5…` |
| `previous_digest` | `sha256:1f47cd62…` — the pre-append head, exactly |
| record digest / new chain head | `sha256:f10dd526fd73b4b321a16d2a439901375b8be67235be4aca61daad75b3d81195` |
| rationale size | 3921 of the frozen schema's 4096-byte cap |

Generator: `internal/deltaledger/definitions_ac2_ruling.go`, registered LAST in
`Definitions()` so every earlier record keeps its sequence, `previous_digest`
and `record_digest`. Rendered by `cmd/deltaledgerctl`; the record is not
hand-written JSON.

### The rationale cites BOTH decisions by digest, inside the hashed preimage

- `us010-016-ac-amendment-owner-decision-2026-08-27.json`, sha256
  `26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974` — the
  operative sentence, with each of its three carve-outs tested against the
  banner clause rather than waved past.
- `us009-us008-owner-decisions-2026-08-27.json`, sha256
  `3a9b24c4b7ee607d981f52e6881ad2476cf03cff01da89bb29461b97f2f99593`, key
  `us009_normativity`, choice `JAVA_FAITHFUL_PLUS_SAFE` — the plane-wide stance
  whose only carve-out is shipped UNSAFETY, enumerated, and a vendor banner is
  none of it.

and it states that **the owner confirmed the reading on 2026-09-04**, which was
the single doubt F010's addendum 3 left open.

Both digests were recomputed here rather than copied from the task:
`sha256sum evidence/governance/decisions/*.json` reproduces both.

### Why the class did NOT move with the disposition

`mismatch_class` stays `underspecified-behavior`, and the record says why in its
own hashed bytes rather than leaving a reader to assume the pair moves together.
Per **F013**, the class names WHERE THE MISMATCH LIVES, not what the port should
do. RFC 6455 §4.2.2 **lists the fields the 101 response is required to carry and
states no rule about whether ADDITIONAL fields may appear** — a list of required
fields is not a closed list — so the RFC genuinely does not settle this
observable. That was true while the disposition was `unresolved` and it is still
true now that a project-level authority has settled what to DO. `java-quirk`
would assert the RFC determines the observable and Java is on the wrong side of
it, and there is no side to be on; `rust-defect` would assert the port is wrong,
which the ruling says it is not.

---

## 2. The append did not disturb history — measured, not asserted

Method: the committed ledger was copied before regeneration, and the two were
compared **record by record** with canonical sorted-key JSON
(`json.dumps(record, sort_keys=True, separators=(',',':'))`).

| check | reading |
| --- | --- |
| records before → after | 58 → 59 |
| **differing set over the 58 pre-existing records** | **`[]` — size 0** |
| `sequence` preserved on all 58 | True |
| `previous_digest` preserved on all 58 | True |
| `record_digest` preserved on all 58 | True |
| frozen prefix, sequence 35 digest | `sha256:3fcd461cfea72e049628a0031bfbb90addecea2f2bb6997e62280cad1962656d` before **and** after |
| top-level keys added / removed | none / none |

The **differing set is empty**, which is the claim the task asked for stated as
the measurement that produces it, not as a summary of one.

A byte-level `diff` of the committed file agrees and is stronger: across the
whole document exactly **one** line is replaced — the top-level `head` — and
everything else is an addition (the sequence-59 record block and the sixth
supersession link). No pre-existing record line is removed or altered.

**`go run ./cmd/deltaledgerctl --root . --check` → EXIT 0**, with
`VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions` exported. Read from
the process:

```
ok: evidence/java/behavior-delta-ledger.json equals the regeneration (59 records, head sha256:f10dd526…, document schema 1.2.0)
ok: evidence/java/ledger-supersessions.json equals the chain's supersession map (6 link(s), also declared in the ledger document)
ok: ledger integrity verified (frozen prefix through sequence 35, … unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
ok: evidence/java/legacy-record-adjudications.json adjudicates records 1-49 … (records_without_ac3_class recomputed = 0 of 59)
ok: evidence/governance/owner-decision-digests.json equals the derivation and 7 governance record digest(s) recomputed from the protected store and matched
```

The gate REFUSES when `VJWP_PROTECTED_STORE` is unset and no store is
discoverable, and that refusal is the design — an unreachable store is
distinguished from a matching digest rather than passing quietly.

### The counters, and which of them are allowed to move

| counter | before | after | verdict |
| --- | --- | --- | --- |
| ledger record TOTAL | 58 | 59 | expected; not a denominator |
| `unledgered_disagreements` | 0 | 0 | unmoved |
| `records_without_mismatch_class` | 49 | 49 | unmoved — 49 sealed preimages cannot gain a field |
| `records_without_ac3_class` | 0 of 58 | 0 of 59 | **numerator unmoved**; only the printed denominator is the record total |
| supersession links | 5 | 6 | expected |
| governance digests mirrored | 6 | 7 | see below |

**No corpus count and no measurement denominator moved.** The 74-row public
corpus, the 247-case Autobahn manifest and the 49-case handshake exam are
untouched by this landing: no case, scenario or seed was added, removed or
re-derived. Nothing here is a re-baseline.

### One derived artifact gained an entry, and it was derived rather than written

`evidence/governance/owner-decision-digests.json` goes from 6 decisions to 7.
`us009-us008-owner-decisions-2026-08-27.json` had **never been cited by any
ledger record** — addenda 3 and 4 of F010 read it, but no hashed rationale
asserted its digest, so the mirror did not cover it and deleting it from the
store would have failed nothing. Sequence 59 cites it, so the derivation now
includes it and `VerifyGovernance` recomputes it from the store. That mirror is
built from the record chain, never hand-maintained; the file was written by
`deltaledgerctl`, not edited.

---

## 3. The follow-on the task predicted: `PLAN_LEDGER_BINDING_MISMATCH`

Reproduced BEFORE fixing it, so the refusal is a reading and not a story:

```
go test ./internal/formalplan/ -run TestConcurrencyPlanArtifactValidates   EXIT 1
  PLAN_LEDGER_BINDING_MISMATCH behavior_delta_ledger.observed_head
    plan records "sha256:1f47cd62…" but the ledger says "sha256:f10dd526…"
  PLAN_LEDGER_BINDING_MISMATCH behavior_delta_ledger.observed_record_count
    plan records 58 ledger records but the ledger has 59
```

Re-bound to the precedent's standard (`ad6a1cb`, and the two re-bindings before
it), and the answer to *how many leaf keys did you touch* is **THREE**:

| leaf key | before → after |
| --- | --- |
| `behavior_delta_ledger.observed_head` | `sha256:1f47cd62…` → `sha256:f10dd526…` |
| `behavior_delta_ledger.observed_record_count` | 58 → 59 |
| `behavior_delta_ledger.append_blocker` | ONE character: *"the ledger now carries 58 divergence records"* → 59 |

A parsed key-level diff over the plan's **781 leaf keys**: those three and no
others changed, **none added, none removed**, and the `bounds` object is
byte-identical, so the conformance statement in `preregistered_plan` holds as
written and no counter in the results document was re-measured.

**What the append_blocker still does not say, disclosed rather than implied.**
The field is **8178 of the schema's 8192-character cap** and its length did not
move (one digit for one digit). Its composition sentence therefore still
enumerates only through sequences 50-56: the paragraph naming 57 and 58 was
removed at the previous re-binding to fit the cap, and there is no room to name
59 either. Trimming another landing's recorded prose to make room for mine is
not a trade this landing takes, so the gap is recorded here and in the results
provenance instead of being paid for out of someone else's paragraph.

`assurance/concurrency/results.json` `preregistered_plan.sha256` re-bound to
`sha256:0b5a73e63b2492e880d6cadc31624ec192febf5ba8505c2447e04156a292730f`
(recomputed with `sha256sum`), with a `sha256_provenance` note recording the
key-level diff, the cap and what the field leaves unsaid. No seed, exploration
or minimized artifact was refrozen.

Linkage refrozen through the sanctioned path, **both exits read**:
`LINKAGE_REGENERATE=1 go test -count=1 ./internal/linkage/` → **EXIT 1** (by
design; it reports the drift it is fixing), then the plain
`go test -count=1 ./internal/linkage/` → **EXIT 0**. One line changed in
`evidence/linkage/evidence-dag.json`, a digest, and non-digest changed lines
**0**.

---

## 4. A SECOND follow-on the task did not predict, and how I proved it was mine

Re-running the whole `internal/formalplan` package after the re-binding showed a
DIFFERENT failure, `TestUS006FixtureCatalogThroughRealCLI` — exit 1, case
`us006-good-backend-executed` realizing to a tree digest other than its frozen
one. Two readings were available: a defect I caused, or drift that was there
before me. I did not guess.

**Isolated by execution.** A second worktree was checked out at the branch base
`6a155a3` and the same single test run there:
`go test ./internal/formalplan/ -run TestUS006FixtureCatalogThroughRealCLI` →
**EXIT 0** at the base, **EXIT 1** on my tree. It is mine.

**The mechanism, read at source rather than guessed.**
`assurance/replay/fixtures/us006-base/mutation.json` copies the repository tree
into every realized fixture, and two of the files it copies are
`assurance/concurrency/plan.json` and `evidence/java/behavior-delta-ledger.json`
— the exact two documents this landing changes. The fixture digest is a
canonical tree hash over the realized copy, so appending one ledger record moves
all 22 of them by construction.

**Refrozen through the sanctioned path, with the precedent named.** `2ed5a28`
is the same refreeze for the same cause at the 57/58 landing, and
`drafts/close-transition-receipt.json` records the same step for the sequence-35
landing before it. Both exits read:
`US006_REGENERATE=1 go test -count=1 -run TestUS006FixtureCatalogThroughRealCLI ./internal/formalplan/`
→ **EXIT 0**, then the full package without the flag (§6).

**Is that a re-baseline the standing rule forbids? No, and the distinction is
the point.** What moved is a set of PINNED DIGESTS over trees that mechanically
contain the documents this landing edited. What did NOT move is any count: the
catalog holds **22 cases before and 22 after**, every case keeps its expected
exit code, state, findings and counters, and the diff is **22 changed lines with
non-digest changed lines = 0**. No corpus grew, no denominator shrank, and no
expectation was relaxed to fit an outcome. Had a case count, an expected
finding, or a scored denominator moved, this section would be a STOP and not a
step.

---

## 5. What else the ruling makes stale — swept, and deliberately narrow

The task asked whether other records, drafts under `drafts/ledger-proposals/`,
or held proposals carried a disposition that assumed F010 was open.

**Ledger chain — swept mechanically, all 58 pre-existing records.** Scanning
every record's serialized delta for `US-011 AC2`, `US-011`, `AC2`, `banner`,
`TooTallNate`, `Server field`, `Date field`:

- **sequence 55** — matches `Date field`. Already superseded by 58 at the
  previous landing. Untouched here.
- **sequence 58** — the only record that names US-011 AC2 at all. Superseded by
  59, which is this landing.

**No third record in the chain touches the subject.** The ruling settles exactly
one open disposition and it has been recorded exactly once.

**`drafts/ledger-proposals/` — all 12 files read.**

- `divergence-sweep-5.json` is the DIV-06 proposal that became sequence 55. Its
  `sweep_recommendation` is `FIX_IN_PORT`; the fix landed as `ddc148d` and the
  ruling now confirms it was the right call. Its `disposition` field is the
  pre-vocabulary placeholder `unresolved`, and `internal/deltaledger/proposal_drafts.go`
  states in as many words that the draft-to-record binding deliberately does NOT
  bind the rationale or the disposition — the draft keeps its proposal and the
  appended record states the adjudication. **Editing it would break a byte
  binding another package verifies and would settle nothing.** Left alone.
- `div06-handshake-response.json` is a closure record dated 2026-09-02, before
  F010 existed. It records what Java does and what the fix did; it takes no
  position on AC2 and holds no disposition. Left alone.
- The other ten carry `unresolved` only as that same pre-vocabulary placeholder
  and none is about this subject.

**Held proposals.** `ProposalDraftPaths()` names seven, all appended at
sequences 50-56 and all bound by recomputed identity. None is about the response
field set. Nothing is held on F010.

**`internal/divergencesweep/classes.go` DIV-06** records
`LandedLedgerSequence: 55` and `Recommendation: RecommendFixInPort`. That is a
true statement about where DIV-06 landed and what the sweep recommended;
re-pointing it at 58 or 59 would be rewriting a sweep's history to follow a
supersession chain, which is widening. Left alone.

**One thing I DID amend, and it is not a ledger record.** `.claude/GOAL-LOOP.md`
carried a US-011 row reading **"AUDITED 2026-09-03, first pass, and it BLOCKS"**
with **"OWNER DECISION REQUIRED"**. The ruling makes that blocking claim false,
and a status board asserting a block that no longer exists is a defect with a
cost. The row now opens by lifting the block and citing sequence 59 and F010's
addendum 5; **the entire superseded audit trail is kept verbatim behind a
strikethrough rather than deleted**, on the same principle as the ledger's own.

**Two things I found and did NOT act on, reported instead of widened:**

1. The GOAL-LOOP **US-010** row says AC4 *"is worth reading beside F010"* and
   left it unaudited. `drafts/self-review/story-criterion-sweep.md` already
   resolves it as **no conflict**, and it was resolved by that sweep, not by
   this ruling. Not mine to close.
2. `drafts/self-review/ledger-adjudication-round.md` and
   `story-criterion-sweep.md` both describe sequence 58 as `unresolved` and the
   chain as 58 records. They are **landing records of past work** and are
   accurate as of the trees they describe. Records are not retrofitted here; the
   supersession is what makes the current state readable.

---

## 6. Every command, with the exit code read from the process

| command | exit |
| --- | --- |
| `go run ./cmd/deltaledgerctl --root . --check` (baseline, before any edit) | **0** — 58 records, head `1f47cd62…` |
| `go build ./...` | **0** |
| `go run ./cmd/deltaledgerctl --root .` (regenerate) | **0** — 59 records, head `f10dd526…` |
| `go run ./cmd/deltaledgerctl --root . --check` (after append) | **0** |
| `go test ./internal/formalplan/ -run TestConcurrencyPlanArtifactValidates` (before re-binding) | **1** — `PLAN_LEDGER_BINDING_MISMATCH` ×2, quoted in §3 |
| `go test ./internal/formalplan/ -run TestUS006FixtureCatalogThroughRealCLI` at base `6a155a3` | **0** — the isolation reading |
| `LINKAGE_REGENERATE=1 go test -count=1 ./internal/linkage/` | **1** (by design) |
| `go test -count=1 ./internal/linkage/` | **0** |
| `US006_REGENERATE=1 go test -count=1 -run TestUS006FixtureCatalogThroughRealCLI ./internal/formalplan/` | **0** |
| `go test -count=1 ./internal/formalplan/` (full package, after both refreezes) | RESULT_FORMALPLAN |
| `go run ./cmd/recordguardctl precondition drafts/self-review/findings/F010-…md` | **0** |
| `go run ./cmd/recordguardctl precondition drafts/self-review/ledger-58-adopt-java.md` | RESULT_RECORDGUARD |
| `make -C rust gates` | RESULT_GATES |

`VJWP_PROTECTED_STORE` was exported to
`$PWD/evidence/governance/decisions` for every ledger and gate run.

### A refusal I hit on the way, recorded because hiding it would be the defect

The first attempt at the F010 addendum opened *"It is no longer P-E-N-D-I-N-G an
owner decision"* — using the word this repository's own record scanner reads as
a record declaring itself unfinished. `recordguardctl precondition` refused the
finding at **exit 1**, naming the line and the term. That is the gate working:
it reads a record's status declaration for its VALUE. The sentence was reworded
to say what it meant and the finding now reads as finished at exit 0. The
refusal is reported rather than quietly edited away, because a gate that fired
correctly on my draft is evidence about the gate.

---

## 7. Ceilings, limits and what this landing does NOT claim

- **No Autobahn run.** Sequence 59's Autobahn preimages are the honest
  NON-EXECUTION markers, byte-identical to the ones sequences 57 and 58 carry.
  Re-running the suite is an owner gate. The record makes no conformance claim.
- **No live Java process** was started, and no port source file was modified.
- **The handshake exam's headline is 49 cases carrying 29 DISTINCT scored
  observations** (23 cases sharing an observation with another, largest class
  10); the public corpus is **74 rows carrying 73 distinct scored
  observations**. Neither number is a claim of this landing — both are quoted
  with their ceilings because a bare `49/49` or `74/74` overstates what was
  independently measured. Neither moved here.
- **The ruling is applied where it was given and nowhere else.** It settles
  US-011 AC2's banner clause and sequence 58's disposition. It does not touch
  US-011 AC1/AC3/AC4/AC5, the sixteen stripped server-handshake checks, or
  US-002 AC5 and US-020 AC2 — the two normativity criteria that sit OUTSIDE the
  amendment's US-010..016 range, which `story-criterion-sweep.md` names as the
  scope gap that lets this class recur. That gap is still open and is not mine
  to close.
- **The test-hygiene point from F010's addendum 2 is untouched by the ruling and
  still unfixed**: a field-count assertion lives inside
  `the_connection_field_echoes_the_requests_value_rather_than_a_literal`, a test
  named for a different property. It was filed as worth fixing *"whatever is
  decided"*, and the decision does not decide it.
- **This branch is based on `6a155a3` as instructed**, while mainline has since
  moved to `8218815` — one commit, which REMOVES the tracked `.quarantine`
  symlink that `6a155a3` still carries. This branch therefore still carries that
  symlink as a tracked entry; it was not touched here and no `git add -A` was
  run. Whoever merges should expect that removal to arrive from mainline's side.
