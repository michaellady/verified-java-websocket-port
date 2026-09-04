# Deciding three of the collision audit's five open candidates — landing record

Branch `claude/collision-candidates-decided`, based on mainline `674c844`.
Follow-on to `drafts/self-review/normalization-collision-audit.md` and to
`drafts/self-review/findings/F007-…`, which argued that three of the audit's
five `HYPOTHESIS` candidates were reachable and that two of the three looked
like refutations.

F007 is an argument. The audit's standard is *decided by construction, not
argument*. This branch runs them.

Deliverables: `internal/normcollide/{refute,expect,utf8}.go` plus the
`refute_test.go` and `live_refute_test.go` gates, the extended
`cmd/normcollidectl`, and a regenerated
`evidence/normalization-collisions/audit.json`.

---

## 1. The three verdicts, each with the seed or proof that decided it

### CAND-WIREBYTES → **REFUTED**, probe `NC-10`

Two seeds, `nc10.col.a` and `nc10.col.b`, both `role: server`, one masked
FIN text frame carrying `hi`:

| | octets | length form |
| --- | --- | --- |
| A | `818201020304696b` (8) | 7-bit, minimal |
| B | `81fe000201020304696b` (10) | 126 extended, **non-minimal** |

Same opcode, same mask key `01020304`, same masked payload octets `696b`. Only
the length encoding differs.

**Measured:** both answered `outcome: ok`. The comparator moved on
`counts.consumed_bytes`, `counts.input_bytes`, `events[0].bytes` and
`frames[0].wire_bytes` — `wire_bytes` 8 versus 10. The distinction is
**represented**, so it is not a collision.

Two facts had to hold together and both did. ws-core really does ACCEPT the
non-minimal form (`framing.rs`'s header records that the Codex codec's
non-canonical-length rejection was stripped for Java fidelity), and the value
really is the consumed span rather than a recomputed minimum
(`core_adapter.rs:1398` passes `frame.wire_bytes` straight through). If ws-core
had REJECTED the extended form, the comparator would still have moved — on
`outcome` — and a careless probe would have called that REFUTED for entirely
the wrong reason. That trap is closed by an explicit check, not by luck: see §3.

### CAND-CHUNKING → **REFUTED**, probe `NC-11`

The same eight octets `818201020304696b`, delivered as one `bytes` step and as
two four-octet steps. Both `ok`. The comparator moved on `events.length` (two
events versus three) and `frames[0].step`.

The run said more than the audit's reasoning did. The reasoning was that
`input_chunk` carries a per-step byte count, which is true — but the delivered
`text` event and the frame record also move from step 0 to step 1, so the split
is visible in three places, not one.

### CAND-UTF8 → **EMPTY**, check `NC-UTF8-PREMISE`

Not "refuted": **no pair exists**. This one could not be decided by exhibiting
two seeds, because the claim is that two such seeds cannot be built. It is
decided by premise checks plus the experiment those premises predict.

I verified F007's premise independently before encoding it, because "no
replacement anywhere" is a claim about a whole tree:

- `rust/ws-core/src` holds 16 `.rs` files. Zero matches for `from_utf8_lossy`,
  `REPLACEMENT_CHARACTER`, `U+FFFD`, `0xFFFD` or `65533`.
- All four `from_utf8` sites in ws-core are strict: `message.rs:188` is the
  text decode (`String::from_utf8(bytes).map_err(|_| Utf8DecodeError)`);
  `handshake/client.rs:181` and `handshake/crypto.rs:94` `.expect` on
  ASCII-guaranteed base64 output; `framing.rs:551` uses `std::str::from_utf8`
  in a `let Ok(…) else` for the close reason.
- `#![forbid(unsafe_code)]` at `lib.rs:55`, so there is no
  `from_utf8_unchecked` route either.

**One correction to F007's premise, and it matters.** F007 argued from ws-core
alone. But the `text` event is MINTED in the harness — `observe.rs:362` sets
`utf8_bytes` from the delivered String — so a lossy conversion introduced
*there* would defeat the emptiness just as completely. The premise checks
therefore scan **both** crates. `rust/ws-oracle-harness/src` is 10 `.rs` files
and also clean.

Encoded as four premises, each with its own measured verdict:

| premise | kind | what it checks | holds |
| --- | --- | --- | --- |
| `U8-P1` | source | the BODY of `pub fn string_utf8` contains `String::from_utf8(` + `map_err` and no lossy marker | yes |
| `U8-P2-rust.ws-core.src` | source | 16 files scanned, 0 lossy/replacement markers | yes |
| `U8-P2-rust.ws-oracle-harness.src` | source | 10 files scanned, 0 markers | yes |
| `U8-P3` | **run** | the discriminating experiment | yes |

`U8-P1` reads the function BODY rather than grepping the file, so a strict call
surviving elsewhere in `message.rs` while the real site turned lossy would not
satisfy it.

**`U8-P3` is the experiment, not decoration on the argument.** The two seeds
are chosen so that a *lossy* decoder maps them onto the SAME `text` event and a
strict one cannot:

- `ncutf8.accepted` carries the three octets `EF BF BD` — the encoded U+FFFD
  itself. Measured: `outcome: ok`, one text event,
  `{"step":0,"text":"\uFFFD","type":"text","utf8_bytes":3}`.
- `ncutf8.rejected` carries a lone `FF` — precisely what a lossy decoder turns
  INTO U+FFFD. Measured: `outcome: error`, `JAVA_INVALID_DATA`, close 1007,
  `frames: 0`, **no text event at all**.

Under a lossy decode both would have read `text` = U+FFFD, `utf8_bytes` = 3, and
CAND-UTF8 would have been a live collision. They do not. The class is empty.

If the decode is ever swapped for a lossy one, `U8-P1` and `U8-P2` go red, the
status recomputes to `HYPOTHESIS`, and the live gate fails — which is what
"the refutation cannot silently rot" means here.

---

## 2. What the decisions do to the two ceilings

**Neither number moves. 73-of-74 and 26-of-49 are unchanged**, because both
shortfalls were already attributed to CONFIRMED probes — NC-04 on
`behaviour.failure` for the public corpus, NC-07/08/09 on `handshake.judged`
for the exam. Saying a refutation *raises* a ceiling would be wrong.

What changes is **what the shortfalls may be blamed on**. All three decided
candidates are `behaviour.ok` distinctions, and all three are represented or
empty there. So:

- No public row is collapsed because of a non-minimal length encoding.
- No public row is collapsed because of how its octets were chunked.
- No row is collapsed because two octet sequences decoded to the same text.
- None of the three is an admissible explanation for either ceiling, and no
  future corpus loses an **ok** row to them.

**The refutations do NOT extend to `behaviour.failure` or
`behaviour.output_limit`**, and the document says so as a scope limit. Those
envelopes carry no `frames[]` and no `events[]` at all, so a rejected frame's
length encoding and a failed request's chunking are erased there — by NC-01's
and NC-02's mechanisms, which already own those classes. A refutation is a
statement about the projection the probe ran on, not about the surface.

Two candidates remain `HYPOTHESIS` and remain admissible explanations, along
with anything the enumeration missed. The claim vocabulary is unchanged:
**BOUNDED**, enumeration not proved complete.

---

## 3. Making a REFUTED verdict as hard to earn as a CONFIRMED one

`Decide` answers one question: did the comparator move? That alone is not a
decision, because there are two ways to move that say nothing about the
candidate. `CheckExpectation` refuses both:

1. **Movement on an unrelated path.** Every refutation probe declares
   `required_diff_paths` — `frames[0].wire_bytes` for NC-10, `events.length`
   for NC-11 — and the run must have moved on them. A refutation earned by an
   incidental difference decides nothing.
2. **Movement because an input was REJECTED.** Neither collision answer may be
   an error row. This is the trap CAND-WIREBYTES walks past: an RFC-strict
   codec rejects the non-minimal form, the pair then differs by `outcome`, and
   `Decide` alone would report REFUTED without anything having shown the
   projection carries the length encoding.

The two catalogs are decided by the SAME `Decide` against the SAME comparator;
only the declared `Expect` differs. `Refutations()` is kept OUT of `Probes()`
on purpose: `Probes()`'s live gate fails on any REFUTED member, and folding a
deliberately-refuted probe in would have meant relaxing that gate. **No
existing check was weakened.** `TestEveryCatalogProbeStillHoldsAgainstTheRealHarness`
and `TestEveryCandidateIsLabelledHypothesis` are untouched and still green —
the latter now guarding two entries instead of five, with the same meaning.

If a refutation ever comes back CONFIRMED, the error says so in those words:
*"That is an ADDITIONAL COLLISION, not a broken check — reclassify it into
Probes() with the count it earns, do not relax this."*

---

## 4. RED readings and deletion attacks

**Eighteen attacks. All mutations are `false &&` or a widened case list, so the
code still compiles — a mutation that breaks the build proves nothing.**

Round 1, thirteen attacks, **eleven RED**:

| attack | disabled | result |
| --- | --- | --- |
| A2 | verdict-vs-expectation check | RED |
| A3 | refutation-names-a-path check | RED |
| A4 | required-path-actually-moved check | RED |
| A5 | rejected-input (error row) check | RED |
| A6 | confirmed-demands-no-movement check | RED |
| A7 | catalog list-declares-its-verdict check | RED |
| A8 | probe-in-both-lists check | RED |
| A10 | decided-candidate status-is-one-we-issue | RED |
| A11 | strict-decode-site premise | RED (both controls) |
| A12 | empty-scan anti-vacuity guard | RED |
| A13 | lossy-marker-found check | RED |
| **A1** | no-expectation check | **GREEN — not load-bearing** |
| **A9** | decided-candidate-has-a-status check | **MUTATION BROKE THE BUILD — proves nothing** |

**All three failures are recorded and fixed structurally, not explained away.**

- **A9 broke the build** (`duplicate case "" in expression switch`). That
  proves nothing. The two switch cases were folded into one membership test
  with two messages, so the guard can be attacked by widening the case list.
  **A9′ → RED.**
- **A1 was GREEN with the check deleted.** The blank-declaration branch is
  subsumed: a blank expectation cannot equal a real verdict, so the
  verdict-comparison check one line below rejects it anyway. Re-aiming the test
  at a bogus expectation against a *real* result was still GREEN (**A1′**). The
  case the guard is uniquely responsible for is a bogus expectation matched by
  an **equally bogus verdict** — every downstream check sails through, and
  without the guard a probe claiming `PROBABLY` is ACCEPTED. **A1″ → RED.**
  The code now carries a comment saying the branch is defence in depth and that
  its catalog-level coverage is A7.

Round 2 attacked the two checks inside `Build`. Both came back **GREEN**, and
for the same reason `PartitionCensus` did in the original audit: a check that
lives only inside `Build` has no default-suite coverage, because `Build` needs
a harness binary.

- **A15** (the decided-candidate status recomputation) → extracted as the
  exported `AssignDecidedCandidateStatuses`, the same move
  `PartitionCensus` needed. Four direct tests now cover it. **A15′ → RED**
  (hardcoding the emptiness status), **A15″ → RED** (making a CONFIRMED
  refutation *close* its candidate instead of reopening it).
- **A14** (`Build`'s `CheckExpectation` call) could not be attacked by deletion
  alone, because every probe behaves and the document comes out identical.
  Attacked from the other side instead — break the PROBE and require the
  pipeline to refuse it:

  | | |
  | --- | --- |
  | **A14a** NC-10's required path changed to `close.code`, which does not move | `normcollidectl write` → **exit 1**, "the comparator did move ([counts.consumed_bytes counts.input_bytes events[0].bytes frames[0].wire_bytes]) — but NOT on [close.code]" |
  | **A14b** same broken probe, `Build`'s `CheckExpectation` call deleted | `normcollidectl write` → **exit 0** — so that call IS what refused A14a |

**The lossy-marker pattern was itself found wrong by a RED reading.** The first
version used `(?i:\bfffd\b)`, which cannot match `0xFFFD` — there is no word
boundary between `x` and `F` — and `TestTheNoLossyScanFindsAPlantedLossyDecode`
caught it on the first run. The pattern now spells out each form
(`u+fffd`, `0xfffd`, `\u{fffd}`, the literal character, `65533`,
`from_utf8_lossy`, `REPLACEMENT_CHARACTER`) rather than approximating with a
word boundary, deliberately avoiding a bare `fffd` that a SHA-256 digest in a
comment would trip. Six planted markers, one per form, are the control.

**The anti-vacuity guard is the one that matters most.** A scan pointed at a
directory with no sources finds zero markers and would otherwise report the
premise HOLDS on the strength of having read nothing. It is refused, the
evidence string says `scanned 0 .rs files`, and A12 proves the guard is
load-bearing.

---

## 5. Tamper attacks and exit codes, read from a built binary

`go run` masks exit codes, so these are from `go build -o nctl ./cmd/normcollidectl`.

```
cargo build -p ws-oracle-harness                              exit 0
normcollidectl verify (untouched document)                    exit 0
normcollidectl report (untouched document)                    exit 0  (9 decided: 7 CONFIRMED, 2 REFUTED)
normcollidectl write  (55798 bytes)                           exit 0
normcollidectl verify, NC-10's verdict flipped to CONFIRMED   exit 1
normcollidectl verify, undecided_candidate_count edited to 5  exit 1
normcollidectl verify, CAND-UTF8 status edited to REFUTED     exit 1
normcollidectl verify, a premise's holds flipped to false     exit 1
normcollidectl verify, document deleted                       exit 1
normcollidectl verify, no --harness                           exit 2
normcollidectl verify --harness /bin/true                     exit 1
normcollidectl, unknown subcommand                            exit 2
go test ./internal/normcollide/                               exit 0
go test -tags normcollide ./internal/normcollide/             exit 0, 30.9s
gofmt -l, go vet on both packages                             clean
```

`report` now exits nonzero on **disagreement with a declaration**, in either
direction — not on "any REFUTED probe", which would have made the refutation
catalog unusable. Two probes are supposed to be refuted.

---

## 6. Provenance note: the harness digest changed

The committed document's `recomputed_from.harness` moved from
`sha256:dd72ee…` to `sha256:9ab570…`. That is this container's rebuild of
`ws-oracle-harness`, not a change to the harness source. I established it
before touching anything: `normcollidectl verify` against pristine mainline
failed on **line 6 only**, and a full regeneration differed from the committed
document in exactly that one line. Every verdict, census number and bound
reproduced byte-for-byte.

---

## 7. What I did NOT do

- **I did not decide CAND-TRANSPORT or CAND-CROSSARRAY.** Both stay
  `HYPOTHESIS` with their original reasons, verbatim.
  `TestTheTwoStructuralCandidatesStayedUndecided` fails if either leaves the
  list. I did find that **both are already decided elsewhere in the tree** —
  written up as `F008` rather than acted on. CAND-TRANSPORT is
  `ac5-collision-server-tcp-close` in `internal/ac5class/register.go`, witnessed
  by `a_server_closes_the_tcp_connection_once_its_close_echo_has_drained`
  (`rust/ws-testee/tests/loopback.rs:1396`); CAND-CROSSARRAY is
  `m013-close-event-order-swap` (`cmd/mutctl/mutations.go:441`), whose register
  entry records `Moves: []` and calls it "a second normalization collision,
  found by this register rather than by a person". **Importing another
  package's verdict into `audit.json` would be exactly the failure this audit
  exists to refuse**, so I did not. The finding proposes a checked
  cross-reference; it does not propose a verdict.
- **I did not run the pinned Java oracle.** One arm only, as in the original
  audit. Nothing here is a Java-versus-Rust fidelity result.
- **No AWS, benchmark or Autobahn run.** Owner gates, never triggered.
- **I did not touch** the ledger, `internal/deltaledger`,
  `assurance/concurrency/results.json`, or `internal/ac5class` — the last read
  only, for F008.
- **I did not weaken any existing check.** `Refutations()` is a separate list
  precisely so the existing live gate keeps its exact meaning. I did EXTEND two
  committed-document tests to span both catalogs and to require the
  candidate arithmetic to close; extending is not relaxing, and both are
  strictly harder to pass than before.
- **I did not adjust any normalization rule**, and did not touch
  `internal/diffregress`, `internal/corpora`, or any Rust source. The two
  refutations are properties of the shipped projection; changing it to produce
  them would have destroyed the evidence.
- **I did not prove the enumeration complete.** Three closed candidates do not
  make the surface table exhaustive, and `claim_vocabulary` still says so.
- **I did not run `make -C rust gates` or any Rust build beyond
  `cargo build -p ws-oracle-harness`.** No Rust source changed.
- **I did not run the full `go test ./internal/...` to completion.** The first
  attempt hit the default 10-minute timeout inside
  `internal/benchplan.TestSchemaAndGoAgreeOnClockSourceForEveryRune` while
  three attack suites were competing for CPU. Only `cmd/normcollidectl`
  imports `internal/normcollide`, so the blast radius is exactly two packages
  and both pass; a `-timeout 40m` scan is the honest way to confirm the rest,
  and the known baseline failures (`internal/lab`, `internal/portplan`,
  `internal/formalplan`, `cmd/formalcoverctl`, `internal/formalcoverage`) are
  not mine.

## 8. Honest notes

The most valuable thing here is not the two REFUTED verdicts — those were
predicted, and a predicted result that arrives is weak evidence. It is the
three checks the deletion attack showed were **not load-bearing**, two of them
in code I had just written and believed was guarded. One broke the build and
proved nothing; two ran green with the check deleted. Had I reported "eleven
attacks, all RED" and stopped, three of the guards in this package would have
been decorative.

The second most valuable thing is `U8-P3`. An emptiness argument is the easiest
kind to fake, because there is nothing to exhibit. Choosing the two seeds so
that a lossy decoder would have collided them is what turns the argument into
an experiment that could have failed.
