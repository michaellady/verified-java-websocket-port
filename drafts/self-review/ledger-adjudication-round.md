# Ledger adjudication round — two records superseded, one decidable record left unwritten, three things still owed by a person

Status: COMPLETE for what it claims, with one deliberate refusal recorded in
section 5, the owner's remaining questions in sections 4, 5 and 6, and a
fourth failing Go package reported rather than absorbed in section 7c.

Branch `claude/ledger-adjudication-2`, worktree `/home/user/vjwp-ledger`, based
on `origin/claude/feature/verified-java-websocket-port` at `c738b81`. Every exit
code below was read from the process that produced it, never inferred from the
text it printed. No AWS run, no benchmark run and no Autobahn run was made, and
no live Java process was started.

---

## 1. What this round did, in one screen

| open item | verdict | what was done |
| --- | --- | --- |
| ledger sequence 34 | **decidable** | superseded by sequence **57** (`adopt-java` / `underspecified-behavior`) |
| ledger sequence 55 | **facts decidable, disposition owed** | superseded by sequence **58** (`unresolved` / `underspecified-behavior`), for a different reason than the one it gave |
| legacy record 19 | **decidable, and NOT WRITTEN** | writing it moves `records_without_ac3_class` from 1 to 0 — hard stop, section 5 |
| ledger sequence 53 | **genuinely the owner's** | no ledger change; the question is stated in one reading in section 6 |

Counted honestly, because the tidy version of this count is wrong. Of the
four, **one** is fully decided here (sequence 34). **One** had its facts decided
and its disposition still belongs to a person (sequence 55, and the person's
question is F010's, restated inside sequence 58's own bytes). **One** is
decidable and deliberately unwritten because filing it moves a published count
(legacy record 19) — so what the owner owes there is an authorisation, not an
adjudication. **One** is a real adjudication only a person can make
(sequence 53).

So three of the four still need something from the owner, and the three things
are different in kind: a ruling, an authorisation, and a ruling again. What
changed is that none of the three now needs a live Java execution, an Autobahn
re-run, or any measurement that does not already exist in the tree.

## 2. The rule this round applied, and where it came from

`drafts/self-review/findings/F013-underspecified-by-the-rfc-recorded-as-underspecified.md`
was read first, as instructed, and it changed how the two classifications below
are WRITTEN rather than being cited beside them. It did not change either class
value; it made each of them say what it means inside its own hashed bytes.

Its finding: `underspecified-behavior` reads as "nothing determines this" and
means "RFC 6455 does not determine this", and the two differ exactly when a
project specification governs an observable the RFC leaves open. The ledger's
authority model has one normative pole (`normative_authority` is enforced to be
`rfc6455` at `internal/lab/ledger.go:137-138`) and three observation sources,
and no field can name this project's own acceptance criteria.

So both superseding records below carry `underspecified-behavior` **with the
scope written into their own hashed bytes**: each says which authority is
silent and, where one is not silent, which one is not. Sequence 58 names
US-011 AC2. Sequence 57 names the recorded `JAVA_FAITHFUL_PLUS_SAFE` fidelity
authority. Neither leaves the class to read itself.

The second rule, from F007: a record saying it needs a ruling is a claim to be
checked, not a fact to be relayed. Each of the four was re-derived from the
tree before its own words were believed.

## 3. Sequence 34 — decided, and superseded at sequence 57

**Subject** `semantic:org.java-websocket.websocketimpl.batch-drain-echo-flush-ordering:provisional-v1`,
`delta-71c02bf6294792a4689c89bbd4c9b859c5667215e311dd6059013e14b7809ee8`,
record digest `sha256:a8bf37b4b9e40dd803b6d36386f5bd50e3035e1d8e51c26e6f3d04b1b4e08f11`.
Inside the frozen prefix, so the correction is a supersession, never an edit.

### What the record says about the port, and why it is false

Its sealed rationale states that "the Rust adapter's typed failure lands before
the completed message's Text event is delivered, so the echo is never enqueued
at all", and that the case is "NOT RESOLVED IN CODE".

Measured on the same wire in one chop:

```
cargo test -p ws-testee --test close_overtakes_echo the_autobahn_5_15_chop
    1 passed; 0 failed          EXIT 0
```

The test that passed is
`rust/ws-testee/tests/close_overtakes_echo.rs::the_autobahn_5_15_chop_now_returns_the_completed_echo_before_the_violation_close`,
and its assertion is the frame shape `[(0x1, 18), (0x8, 2)]` with payload
`fragment1fragment2` and close code 1002 — **the echo first and the violation
close after**, which is shipped Java's order and was not the port's.

What moved it is the DIV-05 fix ledgered at sequence 54:
`ws_driver::InboundFeedPolicy::OneFramePerTurn` (`rust/ws-driver/src/lib.rs`),
which is Java's `decodeFrames` per-frame dispatch loop and is what the
full-stack constructor `connection_driver` selects.

### The part a supersession has to get right: there are two observables

`InboundFeedPolicy::WholeChunk` is still the default and is what
`ws-oracle-harness` uses, because `corpora/public/scenarios.jsonl` scores the
`input_chunk {bytes}` records that policy produces. So the pre-fix ordering
survives as the **oracle** observable while the **full-stack** observable is
Java's. Sequence 57 scopes its claim to the full-stack path — the path Autobahn
5.15 exercises — and names the layer split, which is itself the subject of the
record at sequence 49.

### Why `adopt-java` rather than `unresolved`

Sequence 34 deferred to "an owner fidelity decision". That decision exists and
the same rationale cites it: the recorded `JAVA_FAITHFUL_PLUS_SAFE` authority
makes shipped Java the equivalence target wherever the RFC is silent, holding
back a named list of safety bounds — unsafe code, bounded allocation and
backpressure, checked config limits, and the hard safety ceilings of the merged
design. A dispatch ordering is none of them. RFC 6455 5.4 and 7.1.7 admit both
orderings and the suite classes both as passing, so nothing in the RFC decides
it and the fidelity authority does.

`adopt-java` is also the factual statement: the port reproduces shipped Java,
measured above. It is the same shape as sequence 50, which is an adapter
transport policy the port adopts to match Java.

### Why the class stayed `underspecified-behavior`

Because the class asks where the mismatch **originates**, and it originates in
the RFC's silence about the ordering — which is what the record's own sealed
`rfc_value` preimage says ("unordered: the RFC permits either the
echo-then-fail or the fail-immediately observable") and what
`evidence/java/legacy-record-adjudications.json` entry 34 already filed.

I considered `rust-defect` and rejected it. It would have said the port was
short of its equivalence target, which is arguable; it would also have
contradicted the legacy entry, and rule 9c of
`internal/deltaledger/legacy_adjudication.go:531-538` refuses exactly that
disagreement — "Two adjudications of one subject may not disagree about where
the mismatch originates". The gate would have caught it. It should be recorded
that the gate and the reading agreed rather than that only the reading did.

### What sequence 57 does NOT settle, and says so in its own bytes

Sequence 54 wrote a precondition: *if the reproduction shows the port cannot
enqueue the echo without breaking the ordering ledgered at sequence 34, that
finding supersedes this disposition and the record becomes one for a preserved
ordering.* The DIV-05 landing never tested that antecedent. It took the general
mechanism and did not show a narrower fix impossible. If the owner rules that
the side effect should be reverted, sequence 57's disposition is the thing that
changes, and it is written down so that ruling has something to overturn.

### And it makes no Autobahn claim

Sequence 34 carries **executed** E5/E5b preimages. Those runs measured the
pre-fix subject. Sequence 57's `autobahn_result_digest` and
`autobahn_value_digest` are therefore the honest non-execution markers, and its
rationale says so. Re-running the suite is an owner gate and was not run.

## 4. Sequence 55 — facts decided, disposition still owed, superseded at 58

**Subject** `semantic:org.java-websocket.draft6455.server-handshake.response-server-and-date-fields:provisional-v1`,
`delta-34db0ad7c9378f88a8b9ddd66d76f9d7323c46a13e89ca04bfac51ea6f273830`,
record digest `sha256:beac13463e612e5557d4efa4ca875f20120ef0d7c1cdafe0927dbe6f926d7f57`.

Its rationale opens by stating that "the port's response omits the Server and
Date fields shipped Java adds, and does not sort its field names". Measured:

```
cargo test -p ws-core --test handshake_server_response
    8 passed; 0 failed          EXIT 0
```

Among the eight that passed:
`the_101_response_carries_javas_five_field_names_in_javas_order` (Connection,
Date, Sec-WebSocket-Accept, Server, Upgrade in `String.CASE_INSENSITIVE_ORDER`)
and `the_101_response_is_byte_exact_against_the_pinned_jars_own_output`. The
emission is unconditional at `rust/ws-core/src/handshake/server.rs`
`accept_response`, which writes `\r\nDate: ` and
`\r\nServer: TooTallNate Java-WebSocket\r\n`.

**So the Java-versus-port divergence this record binds is CLOSED**, and the
reason it stood open is gone.

What is open is a different proposition, and it is why sequence 58 keeps
`unresolved`: US-011 AC2 (`docs/prd-pack/07b-child-prd-us009-us019.md:33`)
requires the 101 response to carry the required headers and **no Java-specific
Date or Server banner**. The port now emits precisely those two fields and a
test pins that it does. That is a conflict between the port and a **project
specification**, and the ledger has no field for one — which is F013's gap,
reached from the other side.

Two things this section deliberately does not do:

- It does not claim the `us010-016` AC amendment already settles it. That
  amendment binds AC clauses which require *rejecting, transforming or
  augmenting* behaviour the pinned Java exhibits, and the conflict it was
  resolving is named in its own context field as RFC-strict clauses versus
  Java fidelity. AC2's banner clause is not RFC-derived — RFC 6455 4.2.2
  neither requires nor forbids the fields — so whether the amendment reaches it
  is itself part of the question, not an answer to it. Stretching it to cover
  a clause it was not about would be the mirror of the error F010 filed.
- It does not stack the determinism clause onto the Date half. `accept_response`
  takes the instant as a parameter and reads no clock, so the response is a
  deterministic function of its inputs. F010's addendum got there first and it
  holds up at source.

## 5. Legacy record 19 — decidable, and NOT WRITTEN: a count would move

This is the one I am handing back rather than landing, and the reason is the
standing rule that a count movement is a hard stop.

### The finding: the evidence in the tree answers it

`evidence/java/legacy-record-adjudications.json` entry 19 carries
`examination: evidence-does-not-settle-it`, an empty `mismatch_class`, and a
`blocking_question` that reads, in part: *"Execute the high-bit-64 seed against
the pinned Java-WebSocket 1.6.0 jar ... OWNER ACTION — it needs a live Java
execution, which no gate on this branch may trigger."*

The class turns on one thing: whether pinned Java answers a 64-bit extended
length with the high bit set the way RFC 6455 5.2 requires (a 1002-class
protocol failure) or some other way. The seed is
`rust/ws-core/fuzz-seeds/us012/high-bit-64.hex` = `827f8000000000000000`: FIN,
opcode `0x2` **binary** (not a control frame, so the control-escape rejection
at `Draft_6455.java:617-620` does not apply), marker 127, and eight length
octets `80 00 00 00 00 00 00 00`.

Three committed artifacts answer it together:

1. **An EXECUTED observation against the pinned JAR.**
   `evidence/java/formal-bindings/receipt.json`, run
   `baseline/s.limits.cap-exceeded-16`, request digest
   `sha256:dd726e720246e80fc8bd18fa0c18ec84d3a8a52b7682bf461e5acf0ee33ff66b`,
   response digest
   `sha256:1c972073a7c079764b1240296c83690607802838922dc759677afce8582ba58a`,
   runtime `org.java-websocket:Java-WebSocket:1.6.0`
   `sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f`.
   Input `gn4D6A==` = `82 7E 03 E8`, a declared length of 1000 against
   `max_buffered_bytes: 200`. The response is
   `"error": {"close_code": 1009, "code": "JAVA_INVALID_DATA", "detail": "Payload limit reached."}`
   with `counts.input_bytes: 4`. So the rejection fires **at the length site,
   before any payload arrives**, and pinned Java's observable for it is
   **1009**, not 1002. The clause carries a mutation canary
   (`m.cap.disable-configured-limit`) whose mutant run accepts the frame
   instead, so the observation is not true by construction.

2. **The pinned source, bound by byte span.** The same receipt records
   `translateSingleFrameCheckLengthLimit` as a chain member of
   `obligation.preallocation-cap`, file
   `sha256:39756c4b4f2a548456ba3aebed70639093c930663ca8d6086f10965bd53aaba0`,
   span `23854..24496`, span digest
   `sha256:0e9fd149bb6f5e4a19f8ffd2bfb252280631736706d467b5e57d3644b6a7250c`.
   `assurance/formal/proof-targets.json:143` states what that span does:
   *"length > Integer.MAX_VALUE, length > maxFrameSize, and length < 0 all
   throw LimitExceededException"*. And `:109` states the flow into it: the
   `127 -> 64-bit` form is decoded "via sign-carrying BigInteger parse, with
   the parsed length range-checked in translateSingleFrameCheckLengthLimit".

3. **The port's own citation of the same site.**
   `rust/ws-core/src/framing.rs` `decode_frame_header` documents its 1009 gate
   as `translateSingleFrameCheckLengthLimit :648-663`, and
   `assurance/formal/frame-model.tla:235-237` says it in one line: a declared
   length above maxFrameSize "throws LimitExceededException, which the port
   projects as close code 1009".

A second, independent executed instance of the same projection sits in
`evidence/ac5-class-completeness/java-arm-public.jsonl`: public corpus case
`us005.pub.0031`, family `buffer-limit-frame`, the live Java arm against the
same pinned jar `sha256:eae29213…`, a 7-bit inline length of 80 against
`max_buffered_bytes: 64`, answered
`{"close_code": 1009, "code": "JAVA_INVALID_DATA", "detail": "Payload limit reached."}`
at `consumed_bytes: 2` — the inline length site rather than the 16-bit one. Two
different length sites, two different runs, one exception, one close code. (That
row is one of the 74 public rows, which carry 73 distinct scored observations
between them; nothing here rests on the row being unique.)

**The step that removes the need for a live run.** A 64-bit value with the high
bit set lands in at least one of that helper's three branches under either sign
reading — negative under the signed BigInteger, above `Integer.MAX_VALUE` under
the unsigned one — and **all three branches throw the same exception**. So the
exact branch is unknown and the observable is not: it is the
`LimitExceededException` whose executed close code is 1009. Java is therefore
on the far side of a determinate RFC rule, the port answers 1009 at length site
10 (`rust/ws-core/tests/frame_codec.rs::high_bit_64_length_is_an_ordinary_oversized_length_at_site_10`),
and the class is **`java-quirk`**.

The residual, stated rather than smoothed over: no run put *this seed* through
the pinned JAR. The inference is one executed observation of the exception's
close code plus a source reading that the three branches share the exception.
That settles the CLASS question (is Java on the RFC's side, yes or no) and does
not settle which branch fires.

### Why it is not written

`records_without_ac3_class` is **1 of 58**, and record 19 is that 1. Filing a
class moves it to **0**. That is a published count on a committed evidence
document, so this round stops on the record and reports it rather than making
the movement.

**THE EXACT CHANGE, so the authorisation is a yes or a no and not a research
task.** In `evidence/java/legacy-record-adjudications.json`, entry
`sequence: 19`: set `mismatch_class` to `"java-quirk"`; change `examination`
from `"evidence-does-not-settle-it"` to `"evidence-settles-it"`; replace the
`argument` with the chain above; clear the `blocking_question`, since the
question it asks — execute the seed against the pinned jar — is no longer what
the class turns on; and set the document's `records_without_ac3_class` from 1
to 0. `internal/deltaledger.VerifyLegacyAdjudications` recomputes that residual
rather than trusting the stored integer, so the count cannot be moved without
the class actually being filed. Nothing in the hash chain changes: record 19's
own sealed delta is untouched and carries no `mismatch_class` field either way.

**And what a NO commits the project to**, because the refusal has a cost too:
`records_without_ac3_class` stays at 1 while the tree already contains the
evidence that answers it, so the residual stops meaning "unanswered" and starts
meaning "unfiled" — which is the same distinction F013 is about, one level up.

## 6. Sequence 53 — the one that is genuinely a person's, in one reading

**Subject** `semantic:org.java-websocket.closeframe.invalid-utf8-reason-transport-stall:provisional-v1`,
`delta-7677db91f7b6267d3614468f70abebcb7c119d539297cd58c697e9bc7b7b8dfa`.
It is `unresolved` / `java-quirk` and both are right. Its facts were checked and
are current: `violation_close_verdict` in `rust/ws-driver/src/lib.rs` gates on
`failure.close_code?`, and the invalid-UTF-8 close reason is the Q12
`JavaRuntimeRejection`, which carries no close code — so `compose_violation_close`
returns nothing, `send_violation_close` writes nothing, and
`rust/ws-testee/src/io_loop.rs` shuts the socket both ways. The sequence 51 fix
did not change this path, exactly as sequence 53 predicted it would not.

**THE QUESTION.** May the port hold a TCP connection open, with nothing on the
wire, after receiving a Close frame whose reason is not valid UTF-8, in order
to reproduce shipped Java?

**Candidate answer A — no; the port keeps its prompt close.** Commits the
project to: recording this as an `intentional-correction` or `rfc-governs`
divergence from shipped Java on 1 of 247 server-role cases (0 of 247
client-role), disclosed and kept; and to reading the amendment's
"safety-critical bounds are NOT relaxed" as covering an unbounded hold of a
connection resource driven by a peer that has already misused the protocol.
RFC 6455 8.1 and 7.1.6 are determinate here and the port is the side that
follows them.

**Candidate answer B — yes; reproduce the stall.** Commits the project to:
adding a hold-open path with no bound the port controls (Java has no timer here
— the *peer* times out), on a failure path whose current property is that the
socket is released immediately; to a `fix-in-port` disposition on this record;
and to revisiting the disclosed residual in sequence 51's own rationale, which
already declined Java's indefinite block once ("the flush is bounded by the
write-stall limit where Java's `flushAndClose` would block indefinitely").
Choosing B without revisiting that leaves two failure paths on opposite
principles.

**Why I did not decide it.** The tilt is towards A, and the tilt is an
argument, not a measurement. The amendment's carve-out list is specific —
unsafe code, bounded allocation and backpressure, checked config limits, hard
safety ceilings — and "holding a socket" is none of those verbatim; calling it
one is a reading. Sequence 51's residual is precedent by analogy on a
neighbouring mechanism (bounding a write in progress), not evidence about this
one. Deciding on the strength of a tilt is how a reasoned guess becomes a
finding, which is what F007 praises the collision audit for refusing.

## 7. What moved, what did not, and the ceilings on the numbers used

Counts, read from `deltaledgerctl --check` output:

| count | before | after |
| --- | --- | --- |
| `records_without_mismatch_class` | 49 | **49** |
| `records_without_ac3_class` | 1 | **1** |
| `unledgered_disagreements` | 0 | **0** |
| governance decisions verified | 6 | **6** |
| supersession links | 3 | **5** |
| ledger records total | 56 | **58** |

The last row is the one to read carefully. Appending is the only correction
mechanism the frozen-prefix ruling allows, so the total grows whenever a record
is superseded — sequences 45-47 grew it the same way. All 56 pre-existing
records are byte-identical after the append (verified record by record against
`git show HEAD:evidence/java/behavior-delta-ledger.json`; zero differ), and
sequence 35 is still
`sha256:3fcd461cfea72e049628a0031bfbb90addecea2f2bb6997e62280cad1962656d`.
**No corpus and no measurement denominator moved.** If the owner counts the
record total itself as a protected denominator, the revert is one file
(`internal/deltaledger/definitions_stale_port_corrections.go`), its one-line
hook in `Definitions()`, and a regeneration.

Ceilings on every number used above, stated with the number rather than after
it:

- The **74** public corpus rows carry only **73 distinct scored observations**;
  two of them are indistinguishable, so 74/74 certifies at most 73
  distinguishable answers.
- The **49** handshake cases carry only **29 distinct scored observations**
  (raised from 26 this session), with **23** cases sharing an observation with
  at least one other and the largest equivalence class holding **10**.
- The Autobahn extents quoted from sequences 53 and 55 (1/247 and 247/247
  server-role) are recomputed from committed per-case report bytes by
  `internal/divergencesweep`. They are the pre-fix measurement in sequence 55's
  case, which is why sequence 58 does not restate them as current.
- Sequence 57 and sequence 58 make **no Autobahn claim at all**.

## 7b. The append broke four tests in one package, and one of the four is a finding

`make -C rust gates` was green while `go test ./internal/deltaledger/` was
**exit 1**, which is the exact trap the protocol names: gates green is necessary
and never sufficient. A third failing package is a defect until proven
otherwise, and this one was mine.

Three of the four were pinned counts, and updating them is routine: two in
`internal/deltaledger/integrity_test.go` and one in `mapping_census_test.go`
assert "three supersession links", which is now five. They are updated by
NAMING the five sequences (14, 15, 16, 34, 55) rather than by comparing a
number, so the next append fails with a sequence in the message instead of an
arithmetic complaint. A fourth, `TestAQuotedSupersedesTokenIsNotAWithdrawal`,
took its "record that supersedes nothing" as `Records[len-1]`; the last record
now supersedes sequence 55, so the record is chosen by predicate instead and
the test fails loudly if the premise stops holding.

The fourth failure is worth keeping. `TestUnledgeredCountReportsNonzeroAndTheReadinessGateRefuses`
builds a TRUNCATED chain by removing one definition, and it named sequence 17.
A `Supersession` names its target by **sequence** as well as by delta id, so
removing a definition that sits BEFORE a superseded record renumbers that
record and the link stops resolving:

```
build the truncated ledger: record 56 supersedes sequence 34 naming delta
delta-71c02bf62947…, but sequence 34 is delta-9dd3ab8674…
```

That refusal is correct and is the fail-closed property working. It is also a
DIFFERENT failure from the digest-arm failure the test exists to prove, and it
masked it. The isolated record is now sequence 56, which sits after 55 — the
last superseded sequence — so removing it renumbers nothing that is named, and
the new constraint is written into the test's comment rather than left for the
next person to rediscover. The test's own comment had predicted this shape:
*"If a future change makes it load-bearing, this test fails loudly and a
different isolated record should be named here."* It did, and it did.

Nothing was loosened. No assertion was deleted, no expectation widened to a
range, and the deliberate-failure polarity of each test is unchanged.

## 7c. A FOURTH package fails, it is not mine, and the two-package baseline is not true today

`go test ./... -timeout 40m` exit **1**, with **41 ok** and **four** failing
packages, not two:

| package | cause |
| --- | --- |
| `internal/deltaledger` | **mine**, fixed in section 7b |
| `internal/lab` | the documented Darwin `sandbox-exec` reason |
| `internal/portplan` | the documented vendor decision |
| `internal/formalplan` | **not mine**, and not on the documented list |

Every `formalplan` failure carries the same finding — `JAVA_QUARANTINE_UNAVAILABLE`
at `assurance/formal/proof-targets.json#$.sources.quarantined_java_tree`,
message `JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned HTTP 403`
— across `TestProofTargetsRealDocumentVerifies`,
`TestFormalPreflightRealDocumentDeepRulesClean`, the four `Deep` preflight
tests, the five `CloseDeliveryConsistency` subtests, the three
`SeededDefectsBlockWithTypedFindings` subtests (each reporting
`finding … absent; got [JAVA_QUARANTINE_UNAVAILABLE]`, so the quarantine
refusal is masking the seeded defect the subtest exists to detect) and the
three `TargetsRound1` claims.

Probed directly rather than inferred:

```
curl https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a777aed862f2f5b5cf060cae7969958667.tar.gz
    http=403  bytes=378
    {"message":"GitHub access to this repository is not enabled for this session. …"}
    sha256 b3e03aaaff81d68730d67392a135ac3fdfdf022880c66632ab188d2fe084cda3
```

That is the pinned source archive named in `evidence/intake/source-pins.json`
(`java-websocket-source-archive`, pinned `sha256:f44e7647…13cb4`), and the 378
bytes and their digest are byte-identical to the refusal the DIV-05
continuation recorded for the same URL. `.quarantine/` is empty and git-ignored.

**Why this is proven not to be mine.** The diff on this branch touches
`internal/deltaledger/` (one new definitions file, one hook line, three test
files), `evidence/java/behavior-delta-ledger.json`,
`evidence/java/ledger-supersessions.json`,
`evidence/java/legacy-record-adjudications.json`,
`evidence/governance/owner-decision-digests.json` and two records under
`drafts/self-review/`. None of those is read by the quarantine acquisition
path, and the failure is a network refusal from the session proxy rather than
a content mismatch.

**EXACT ACTION NEEDED, and it is not mine to take.** The session has no GitHub
access to `TooTallNate/Java-WebSocket`, so `internal/portplan.EnsureQuarantinedSource`
cannot acquire the pinned tree and every Java-source-anchored formal check
fails closed. Attaching that repository to the session would turn the package
green by *acquiring quarantined third-party source mid-round*, which changes
what the evidence plane can see and is governed by the acquisition lifecycle in
`evidence/intake/source-pins.json` (expiry 2026-09-23, "fail closed on
artifact, tool, license, policy, repository, role, identity, or
vulnerability-state revocation"). I did not do it. The two-package baseline
statement is therefore FALSE on this branch today, and it is reported rather
than amended — which is the rule the protocol states for exactly this case.

## 8. Exit codes, each read from the process

| command | exit |
| --- | --- |
| `git worktree add /home/user/vjwp-ledger -b claude/ledger-adjudication-2 …` | 0 |
| `go run ./cmd/deltaledgerctl --root . --check` (baseline, before any change) | 0 |
| `cargo test -p ws-testee --test close_overtakes_echo the_autobahn_5_15_chop` | 0 |
| `cargo test -p ws-core --test handshake_server_response` | 0 |
| `go run ./cmd/deltaledgerctl --root . --check` (after the definitions, before the write) | **1** |
| `go run ./cmd/deltaledgerctl --root .` (the write) | 0 |
| `go run ./cmd/deltaledgerctl --root . --check` (after the write, before the legacy entry) | **1** |
| `go run ./cmd/deltaledgerctl --root . --check` (after the legacy entry) | 0 |
| `go build ./...` | 0 |
| `make -C rust gates` | 0 |
| `go test ./internal/deltaledger/ -timeout 40m` (after the append, before the test updates) | **1** |
| `go test ./internal/deltaledger/ -timeout 40m` (after the test updates) | 0 |
| `go run ./cmd/recordguardctl precondition drafts/self-review/ledger-adjudication-round.md` | 0 |
| `go test ./... -timeout 40m` (whole suite) | **1** — 41 ok, four failing packages, section 7c |
| `curl` on the pinned Java source archive | http 403, 378 bytes |

Both exits of the regeneration are recorded, and so is the second refusal: the
gate rejected the append until
`evidence/java/legacy-record-adjudications.json` entry 34 declared
`contests_record_basis` and `superseded_by_sequence: 57`, which it re-derives
from the records' own hashed rationales rather than taking on the entry's word.
That refusal is the mechanism working, and it is recorded because a round that
only shows its green runs has hidden half of what it learned.

`VJWP_PROTECTED_STORE` was exported to `$PWD/evidence/governance/decisions` for
every `deltaledgerctl` invocation above; without it the governance arm refuses
by design, and that refusal is the design.

## 9. What this record does not claim

- It does not claim any Autobahn result. The suite was not run, and both new
  records carry the non-execution markers rather than inheriting the E5/E5b
  preimages that measured the pre-fix subjects.
- It does not claim a live Java observation. The section 5 argument rests on
  one previously executed oracle run plus a byte-span-bound source reading, and
  says which is which.
- It does not claim that sequence 57's `adopt-java` is the end of the matter.
  Sequence 54's untested precondition is named inside sequence 57's own hashed
  rationale precisely so a reverting ruling has a target.
- It does not claim the `us010-016` amendment settles US-011 AC2. Section 4
  says why that stretch was declined.
- It does not re-baseline anything. No corpus, no denominator and no expectation
  was adjusted.
