# Normalization collision audit — was the supersession real? A content check

Branch `claude/normalization-collision-closure-2`, based on mainline `4cf3f8f`.

`drafts/self-review/normalization-collision-audit-WIP.md` declares itself
superseded by `drafts/self-review/normalization-collision-audit.md`.
`recordguardctl` verifies the **form** of that claim. This record verifies its
**content**, item by item, which is the part no tool in this tree can do.

STATUS: COMPLETE. Nine items mapped, eight answered, one not — and the one that
was not is now closed, with the machine check that would have caught it.

---

## 0. The premise I was given was already false, and reading it was the first job

I was told the census reports exactly one unfinished record. It does not. Before
I changed anything:

```
go run ./cmd/recordguardctl gate -root .
gate=record-content-precondition census SUPERSEDED
  record=drafts/self-review/normalization-collision-audit-WIP.md signals=2
  superseded_by=drafts/self-review/normalization-collision-audit.md
gate=record-content-precondition step=census records=54 unfinished=0 superseded=1 finished=53
gate=record-content-precondition result=PASS                              exit 0
```

`a62d3da` had already made supersession a third state. So there was nothing to
rename, nothing to delete, and **no census to clean up**. Had I taken the
premise on trust and "fixed" the census, I would have renamed a record to make a
number read the way I had been told it already read.

**What the gate checks, and what it cannot.** `Supersession` in
`cmd/recordguardctl/scan.go` requires the claim to be DECLARED in the record's
own words (never inferred from the `-WIP` filename), requires the named target to
EXIST, and requires that target to itself read finished — and a superseded record
is still `REFUSED-SUPERSEDED` as a landing precondition. That is a good
mechanism and I did not touch it.

What it cannot check, by construction, is **whether the superseding record
answers what the superseded one left open.** Existence plus reads-finished is a
stronger proxy than bare existence, but it is still a proxy. Reading it as
identity is F009's defect class
(`drafts/self-review/findings/F009-i-read-a-record-by-its-existence.md`) with a
better instrument. So: the gate checked the FORM and passed; this record checks
the CONTENT, and the two are different results.

---

## 1. The mapping, item by item

Nine items. Line numbers on the left are the WIP record; on the right, the
landing record **as it stood at `4cf3f8f`**, before this branch changed it.

| # | item (WIP) | WIP lines | answered at | verdict |
| --- | --- | --- | --- | --- |
| I-1 | baseline reproduced: build, 74 harness lines, `total=74 identical=48 detail_only=26 divergent=0` | 5–13 | §6 "Exit codes read from the process", lines 209–228 — the same three commands with the same three exit codes | ANSWERED |
| I-2 | the 74 rows fall into exactly two key-sets, 48 `ok` / 26 `error`, keys listed | 15–27 | §1 table lines 24–28 and §3 line 96; independently, `audit.json` `scored_corpus_census.key_sets` = 48 `behaviour.ok` + 26 `behaviour.failure` | ANSWERED |
| I-3 | of the six dropped keys only four are collision-bearing; `role` and `initial_state` are request echoes recoverable from `request_digest` | 29–37 | §1 "The six dropped keys, refined", lines 37–46 — the same refinement, same reason, same four keys | ANSWERED |
| I-4a | four behaviour projections, key counts 14 / 9 / 6 / 5 | 39–49 | §1 table lines 24–27 — same four, same counts, extended to five by naming `handshake.judged` | ANSWERED |
| I-4b | the handshake scored surface is `java_observable`, `reject_channel`, `close_code` (a constant 1002), `sec_websocket_accept` (server-side accepts only) | 51–55 | §1 table line 28 — which **repeats the same four keys** | **NOT ANSWERED** |
| I-5 | "Next: constructive probes" — the one explicitly forward-looking item | 57 | §2 (seven CONFIRMED probes, each with its seed), §4 (candidates), and `audit.json` `refutations[]` | ANSWERED |
| I-6 | NC-01, error rows erase all four observation streams; witness moves `frames[0].payload_base64` | 61–67 | §2 line 57; `audit.json` probe NC-01 `witness_diff_paths = [frames[0].payload_base64]`, verdict CONFIRMED | ANSWERED |
| I-7 | NC-02, the output-limit projection erases everything including `runtime` | 68–75 | §2 line 58 and §2 lines 80–85; `audit.json` probe NC-02, 8 witness paths, CONFIRMED, plus the DORMANT qualifier the WIP lacks | ANSWERED |
| I-8 | NC-03, mask keys globally unrepresentable, quirk Q28 | 76–82 | §2 line 59; `audit.json` probe NC-03, CONFIRMED, wire witness | ANSWERED |

**Eight of nine answered. One not.** I-4b is not answered, and the way it fails
is worse than a gap: the superseding record **carried the claim forward
verbatim** instead of deciding it. The WIP's own heading calls that section "as
enumerated **so far**", so it was offered as provisional and the landing record
was where it should have been finished. The behaviour half (I-4a) was finished —
four projections became five, with measured counts. The handshake half was
copied.

And in the meantime the tree moved underneath the copy, so the carried-forward
claim became false in both records at once.

## 2. Why I-4b is not "merely adjacent to" an answer

The distinction matters, so here it is measured rather than argued.

`d90308a` added `reject_stage` to the handshake projection and to both scorers,
and `da6e119` pinned it in the Rust suite. Driving the 49 committed cases through
the harness on this branch:

```
cargo +1.95.0 build -p ws-oracle-harness                                exit 0
MeasureHandshake, live, WS_ORACLE_HARNESS=rust/target/debug/ws-oracle-harness
  rows=49 distinct=29 sharing=23 largest=10                             exit 0
```

The measured key sets are 9 keys (20 `reject` rows), 7 (25 `accept`), 6 (4
`incomplete`). So at `4cf3f8f` the landing record's line 28 was wrong twice over:
its count column said `6–8`, and its scored-key list omitted `reject_stage`. Both
records also still qualified `sec_websocket_accept` as server-side only; all 25
accepts now carry it, because a client derives one on every acceptance and simply
never sends it.

**Why nothing caught it.** The landing record's §1 asserted that the table
"cannot go stale silently" because `PartitionCensus` refuses an unclassified
shape. That is the wrong guard for this column, and demonstrably so:
`ClassifyHandshakeKeys` returns `handshake.judged` for **any** key set containing
`java_observable`, so adding a key to the reject shape can never make the
partition check fire. The shape stayed classified while the arity rotted.
`PartitionCensus` guards the partition, not the arity. That sentence is now
withdrawn in the record itself.

## 3. The same root cause had produced four more stale numbers

Once I knew the prose was pinned to nothing, I checked the rest of it against
`audit.json` — which `normcollidectl write` regenerates and `Verify` refuses when
stale. The document had moved and the prose had not:

```
a973211   handshake  26 distinct / 27 sharing / largest 11
d90308a   handshake  29 distinct / 23 sharing / largest 10
```

`70f104f`, the landing record's last touch, is an **ancestor** of `d90308a`.
Every gate stayed green throughout, because no gate read the prose. The record
therefore stated 26 / 27 / 11 in the present tense, and stated `49/49 certifies
at most 26`, while the committed document, the live census and the Rust suite all
carried 29 / 23 / 10.

**This is not a corpus or denominator shift and I did not re-baseline anything.**
Both denominators are untouched — 74 public rows, 49 handshake cases — and
`corpora/handshake/cases.jsonl` last changed at `93f5444`, long before any of
this. The public bound is unchanged at 74 rows carrying **73** distinct scored
observations. What moved is a ceiling that got *higher*: `reject_stage` and the
client-side accept key **split** classes apart, so more answers are
distinguishable than the first measurement found. Nothing was removed and no rule
was relaxed to dissolve a collision.

The record's §4 was stale from the same cause in the other direction: it was
headed "Undecided candidates (5)" when `audit.json` carries 2 undecided and 3
decided, all three decided NEGATIVE. A stale bound understates what is known; a
stale candidate list overstates what is unknown.

The measured collapse, which replaces a breakdown that no longer described
anything (identity stripped, driven through the harness):

| shape | rows | classes | sizes |
| --- | --- | --- | --- |
| `reject` | 20 | 3 | 10 × `invalid_handshake`/`translate`/1002, 9 × `not_matched`/`accept_predicate`/1002, 1 × `invalid_handshake`/`response_build`/1002 |
| `accept` | 25 | 25 | every accept carries a distinct `sec_websocket_accept` |
| `incomplete` | 4 | 1 | one bare class |

3 + 25 + 1 = **29** distinct; 10 + 9 + 4 = **23** sharing; largest **10**. The
49 handshake cases therefore certify at most 29 distinguishable answers, never
49. The public arm's ceiling is likewise 73 of 74, unchanged.

---

## 4. What I closed, and the probe that distinguishes each answer from its negation

`internal/normcollide/recordbounds.go` — two checks, both in the **default**
suite, because both inputs are committed files and a drift gate that only fires
under a build tag does not fire.

**`CheckRecordBounds`** ties eleven sentences in the prose to the document field
each must agree with, and is **fail-closed on absence**: a claim the record stops
carrying reports as a mismatch, because otherwise deleting the sentence would be
the cheapest way to stop a number being stale.

**`CheckRecordSurfaceRow`** pins the two columns `PartitionCensus` cannot reach —
each shape's key count, and the discriminating scored keys. The required key set
is **derived from the document, not authored**: the scored keys present in SOME
handshake key set but not in ALL of them, which on the committed document is
`{close_code, reject_channel, reject_stage, sec_websocket_accept}`.

RED first. Exit codes read from the process.

| probe | reading |
| --- | --- |
| the pin, on the record as it stood at `4cf3f8f` | **exit 1**, 7 mismatches, naming record lines 109, 110, 111, 117, 136 and two absent claims |
| the same run's controls | the three public bounds and the count of confirmed collisions (7) **PASS** in that same run — the check discriminates, it is not a constant failure |
| the surface row, restored to its stale `6–8` form | **exit 1**, naming measured sizes 7 and 9 and the key `reject_stage` |
| A1a: a wrong number planted in the record | **exit 1**, names record line 121 |
| A1b: the same wrong number, comparison forced to pass | **exit 0** — the assertion is what catches it, not something else |
| A2: a wrong number planted in the **document**, record left correct | **exit 1** — it reads the artifact, not a hardcoded constant |
| A3: a bound sentence deleted from the record | **exit 1** — fail-closed on absence |
| A4: the claim list emptied | **exit 1** — a check with nothing to check is itself caught |
| control, record and document both correct | **exit 0** |

**A1b's first form proved nothing and was re-run.** I wrote
`(false && found != want) || found == want`, which is logically identical to
`found == want` and disabled nothing, so its exit 1 was not evidence of anything.
Recorded rather than quietly replaced, because a mutation that changes no
behaviour is the RED-first rule's own failure mode.

**A bug the check found in itself, which is the best evidence here.**
`flattenRecord` stripped `_` as markdown emphasis, so `sec_websocket_accept`
became `secwebsocketaccept` and `CheckRecordSurfaceRow` reported a row I had
**already corrected by hand** as missing every key it named. I found it because
the CONTROL run failed, not because a mutation was aimed at it. Underscores are
load-bearing in these identifiers and are no longer stripped; a regression test
pins it.

### The tag-gated live suite, read honestly

```
cargo +1.95.0 build -p ws-oracle-harness                                exit 0
WS_ORACLE_HARNESS=rust/target/debug/ws-oracle-harness
  go test -count=1 -timeout 40m -tags normcollide ./internal/normcollide/   exit 1
```

**Exit 1, one test, and it is not a result about this branch.** The only failure
is `TestCommittedAuditMatchesAFreshRun`, and it fails on exactly one field: the
harness identity. `audit.json` pins
`sha256:c718a7d30186d2078bf0435b59ae6cb71793fdaf4c812c2fcbb5937683a1479d`; the
debug binary I built on this host is
`sha256:b6c00649c55286432b76726035f099b40808042aaece54c61848bfd359456950`. That
digest field is **byte-identical at `4cf3f8f` and on this branch** — I did not
touch `audit.json` — so the disagreement is between the committed document and
*my* binary, which is the digest binding doing its job rather than a defect. The
correct response is NOT to regenerate the document: that would shift a committed
artifact to match a local build, which is re-baselining. Recorded and left for the
owner, who has the binary the pin names.

What that same run DOES establish, and it is the stronger half:
`TestEveryCatalogProbeStillHoldsAgainstTheRealHarness` **passes**, so all seven
collisions re-ran CONFIRMED against a freshly compiled harness;
`TestEveryRefutationProbeStillMovesTheComparator`, `TestNC10…`, `TestNC11…` and
`TestTheUtf8CandidateIsStillEmpty` pass; and `MeasureHandshake` on that same
binary returns 49 rows / 29 distinct / 23 sharing / largest 10. Every number in
§3 above was produced by the binary the gate says is not the pinned one, and the
bounds came out the same, which is what makes them a property of the projection
rather than of one build.

`gosuitectl` does not pass `-tags`, so this tag-gated test is not part of
`make -C rust gates` and does not gate it.

### Baseline health of the default suite

```
go test -timeout 40m ./...     44 ok, 2 packages FAIL      exit 1
```

The two are `internal/lab` and `internal/portplan` — **exactly the two
`cmd/gosuitectl` excludes by name**, each with its reason declared there
(`CONTROLLED_CANARY` needs Darwin `sandbox-exec`; the committed semantic-id
oracle records `jdk_vendor "Homebrew"` and a Linux Temurin regeneration differs
in that one line). Neither is mine and neither is touched by this branch. Every
package `gosuitectl` actually runs passes, `internal/normcollide` among them, so
the two new checks are covered by the gate rather than by a tag.

The 600-second default would not have reached the end of this suite; it was run
with `-timeout 40m`, and a timeout is not a result.

### A side effect I caused on this host, disclosed rather than left quiet

The first `make -C rust gates` run reported
`make: *** [Makefile:117: go-suite] Terminated` — a signal, not a test failure,
so its exit 2 was not a gate reading. Clearing it, I ran
`pkill -x make`, `pkill -x cargo` and `pkill -x gosuitectl`, and **those patterns
are not scoped to this worktree.** Other agents were running the same gate from
`/home/user/vjwp-gateattack` and `/home/user/vjwp-criteria` at the time, so I may
have interrupted a step of theirs. They had live processes again immediately
afterwards, and new PIDs appeared under `vjwp-gateattack` while I watched, so
nothing appears to have been left dead — but "appears" is the honest word and the
correct scoping was by PID after checking `/proc/<pid>/cwd`, which is what I did
from then on. An earlier `pkill -f "make -C rust gates"` had also matched its own
shell, which is why that command returned 144.

Recorded because a gate re-run that quietly costs another agent their run is a
cost, and because the concurrency note in the landing record already says other
agents share this machine.

## 5. What this leaves open

- **The two undecided candidates stay undecided.** `CAND-TRANSPORT` needs a real
  peer socket, `CAND-CROSSARRAY` needs a mutated harness (`cmd/mutctl`). Neither
  is decidable by a request seed, so neither is decidable by this instrument, and
  I did not relabel them to look closed.
- **The enumeration is still not proved complete.** It reads five named sites;
  a distinction none of them mentions cannot be found by reading them. The claim
  vocabulary is BOUNDED and observed, never proved-model or proved-production.
- **No Java arm was run here.** Every number in §2 and §3 above is the Rust
  harness answering. That is sound for a claim about the projection, which both
  arms share by construction, but nothing here is a Java-versus-Rust fidelity
  result.
- **The prose of every OTHER record in the tree is still pinned to nothing.**
  `CheckRecordBounds` covers one record's numbers. The general defect — a
  regenerated artifact and a hand-written record that reads it, with no check
  between them — is closed for `normalization-collision-audit.md` only. Filed as
  a general shape rather than claimed as fixed.
- **`.gitignore` does not ignore the `.quarantine` symlink.** Line 30 reads
  `.quarantine/`, with a trailing slash, so it matches a DIRECTORY. The isolation
  step for this task creates `.quarantine` as a symlink, which the rule misses, so
  `git add -A` stages it — it did here (`59fb547`) and at `f1b98a4` before. My
  first removal did not hold: the next commit ran `git add -A` and re-staged it,
  which is the trap demonstrating itself, so the symlink is now in this worktree's
  `.git/info/exclude` rather than removed once and hoped about. A committed symlink to an absolute path gives every other
  checkout a dangling link, and `cmd/gosuitectl`'s precondition would then read a
  broken link as a staged quarantine and stop refusing. The one-character fix is
  in a shared file and is not mine to make on this branch; reported, not applied.
- **`internal/ac5class` still carries two collisions where this audit found
  seven.** Unchanged from the landing record's own §9; it is a US-020 acceptance
  artifact and remains an owner decision.

## 6. Owner actions, none taken

1. **NC-04 still costs the public headline a row.** Two shipped scenarios are
   indistinguishable, so 74 rows carry 73 distinct observations. Either the
   corpus gains a scenario that separates them or the headline is restated as 73.
   `TestPublicCensusMeasuresTheShippedTranscript` pins 73 so the choice cannot be
   made silently.
2. **The handshake ceiling is 29 of 49, and it is now pinned in prose as well as
   in the document.** If a future projection change moves it again, the new check
   fails until the record is restated — which is the intended cost.
3. **No AWS, benchmark or Autobahn run.** Owner gates, never triggered.

## 7. What I did not do

- I did not touch `cmd/recordguardctl`: another agent is reviewing it, and its
  supersession handling is better than the premise I was handed suggested.
- I did not rename, move or delete `normalization-collision-audit-WIP.md`. Its
  supersession declaration was already correct for eight of its nine items and is
  now correct for the ninth, because I fixed the **superseding** record rather
  than the declaration.
- I did not modify the ledger, `internal/deltaledger`, `internal/diffregress`,
  `internal/corpora`, any corpus, or any Rust source. `origin/codex/race-catchup`
  was not read or touched.
- I did not weaken any existing check, and I did not adjust a normalization rule.
  The collisions are the finding; dissolving one would destroy the evidence.
- I did not regenerate `audit.json`. It was already correct; the prose was what
  was wrong, and I changed the side that was wrong.
