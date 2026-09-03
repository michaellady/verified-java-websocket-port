# story-criterion sweep — is F010 one instance or a class with members?

phase: systematic sweep for the F010 defect class   date: 2026-09-03
branch: `claude/story-criterion-sweep`, worktree `/home/user/vjwp-criteria`,
based on mainline `claude/feature/verified-java-websocket-port` at `4cf3f8f`.
Every exit code below was read from the process, never from a pipe and never
from a summary line.

**The class, as F010 defines it:** a divergence fix verified exhaustively
against Java, and never against the story criterion that governs it. Fidelity
to Java standing in for correctness. DIV-06 made the port emit `Date` and
`Server: TooTallNate Java-WebSocket`, which US-011 AC2 forbids in as many words.

**The answer, in one line:** ONE further instance, and it is narrower than
F010; and the most consequential thing this sweep found is not a second
instance at all but a document F010 does not cite, which changes what the owner
is actually being asked to decide about F010 itself.

---

## 1. The criteria that constrain observable port behaviour

The child PRD carries **136 acceptance-criterion bullets** across 27 stories
(counted mechanically off `docs/prd-pack/07{a,b,c}-*.md`: 5 per story except
US-009 with 4 and US-023/US-027 with 6). I read all 136 and carried **39** into
the cross as constraining observable port behaviour — wire bytes, close codes,
header sets, event ordering, state transitions, or which endpoint acts. The
enumerated 39, so a later round can dispute the classification rather than
re-derive it:

| story | clauses carried | clauses left out, and why |
|---|---|---|
| US-002 | AC5 (second half only) | AC1–AC4 are oracle-build provenance |
| US-009 | AC2, AC3, AC4 | AC1 is workspace infrastructure |
| US-010 | AC1, AC2, AC3, AC4 (second half) | AC5 is migration-map linkage |
| US-011 | AC1, AC2, AC3, AC4 (second half) | AC5 is reconciliation linkage |
| US-012 | AC1, AC2, AC3, AC4 (second half) | AC5 is formal-run machinery |
| US-013 | AC1, AC2, AC3 | AC4, AC5 are evidence machinery |
| US-014 | AC1, AC2, AC3 | AC4, AC5 are evidence machinery |
| US-015 | AC1, AC2, AC3 | AC4, AC5 are evidence machinery |
| US-016 | AC1, AC2, AC3 | AC4, AC5 are evidence machinery |
| US-017 | AC1, AC2 | AC3, AC4, AC5 are exploration/stress machinery |
| US-018 | AC1, AC2, AC3, AC5 | AC4 is integration reconciliation |
| US-019 | AC3 (strict-pass half) | AC1, AC2, AC4, AC5 are run mechanics |
| US-020 | AC2, AC3 (class half) | AC1, AC4, AC5 are harness/detection |
| US-024 | AC1, AC4 | AC2, AC3, AC5 are replay machinery |

Process criteria — how work is recorded, which digest binds what, which
manifest reconciles — are deliberately out of scope per the task, and that is
where US-001, US-003 through US-008, US-021, US-022, US-023, US-025, US-026 and
US-027 land in their entirety.

### The sub-list that actually decides this sweep

Of the 39, only a handful require the port to do something OTHER than what
shipped Java does. Those are the only clauses the F010 class can be built from:
a criterion the port satisfies by being Java-faithful cannot be violated by
being Java-faithful. I extracted that sub-list mechanically rather than by
recall —

```
grep -n "Java" docs/prd-pack/07{a,b,c}-*.md \
  | grep -iE "not emulat|no Java|never|rather than|cannot|quirk|defect|leniency"
```

— and the complete anti-Java-fidelity set in the child PRD is **five AC clauses
plus one story goal**:

1. **US-002 AC5** — *"Every Java/RFC/Autobahn disagreement is preserved in the
   append-only Behavior Delta Ledger; Java is never treated as normative when it
   conflicts with RFC 6455."*
2. **US-010 AC4** — *"RFC-derived public/hidden vectors and Java differential
   observations cover valid and invalid behavior; any Java/RFC mismatch is added
   to the delta ledger rather than copied."*
3. **US-011 AC2** — *"A valid request emits a deterministic 101 response with the
   exact Sec-WebSocket-Accept, required headers, no Java-specific Date or Server
   banner, and a normalized semantic handshake event."*
4. **US-011 AC4** — *"RFC-derived, independent-parser, and Java differential
   vectors cover valid and invalid paths with arbitrary chunking; Java leniency
   cannot lower the RFC gate."*
5. **US-012 AC4** — *"Autobahn categories 1, 3, 4, and 10 plus neutral
   differential/property/fuzz/runtime cases exercise the exact shipped symbols;
   Java's known unmasked-input leniency is classified as a quirk, not emulated."*
6. **US-020's story goal** — *"…adjudicated by the oracle hierarchy so that
   parity is complete without preserving Java defects."* A goal, not an AC.

Plus one adjudication rule that is not anti-fidelity but ranks the RFC above
Java: **US-020 AC2** — *"RFC 6455 is rank one, in-scope Autobahn is rank two,
independent neutral expectations are rank three, Java observation is rank four,
and Rust observation is rank five; agreement between Java and Rust cannot
override a higher oracle."*

That set is the whole surface. It is six clauses wide, and it is why this sweep
can bound its own negative rather than wave at it.

---

## 2. The behaviour-bearing fixes, and the document that governs most of them

`evidence/java/behavior-delta-ledger.json` holds **58 records**. Dispositions:
52 `unresolved`, 2 `adopt-java`, 3 `fix-in-port`, 1 `intentional-correction`.

**`unresolved` does not mean "open question" here, and reading it that way would
wreck the whole cross.** `internal/deltaledger/definitions.go:24-29` says why:
the frozen 1.0.0 vocabulary admits only `unresolved` and `rfc-governs`, so
*"records therefore carry disposition `unresolved` — the divergence is
deliberately retained under the owner's JAVA_FAITHFUL_PLUS_SAFE decision, not
resolved toward the RFC."* Sequences 1–49 are therefore all **adopted-from-Java
behaviours that shipped**. F010's own subject, sequence 55, is `unresolved` while
its fix is on mainline. So the correct denominator for step 3 is **all 58
records**, not the 6 with a modern disposition.

Cross-checked against the DIV series in `internal/divergencesweep/classes.go`:
DIV-01→seq 51, DIV-02→seq 52, DIV-03→seq 53, DIV-04→seq 34, DIV-05→seq 54,
DIV-06→seq 55 (superseded by 58), DIV-07→seq 56.

### The governing document, which F010 does not cite

`evidence/governance/decisions/us010-016-ac-amendment-owner-decision-2026-08-27.json`,
decided **2026-08-27T21:42:50Z**, sha256 `26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974`:

> **decision:** "AMEND ACs TO JAVA-FAITHFUL: every AC clause of US-010..US-016
> that requires rejecting, transforming, or augmenting behavior which the pinned
> live-verified Java-WebSocket 1.6.0 exhibits is amended to bind instead to the
> recorded fidelity authority… Safety-critical bounds are NOT relaxed…
> Evidence-machinery clauses… are NOT waived by this amendment — only the
> behavioral stance is amended."

> **context:** "…multiple AC clauses of US-010..US-016 encode RFC-strict
> behaviors (**mask/noncanonical-length rejection, RFC close-code table + echo
> matching, RFC handshake validation gate, automatic-pong policy, control payload
> caps**) while the owner's recorded normativity decision for this plane is
> JAVA_FAITHFUL_PLUS_SAFE…"

Behind it sits the plane-wide stance, `us009-us008-owner-decisions-2026-08-27.json`
key `us009_normativity`: *"The port mirrors shipped Java-WebSocket 1.6.0
observable behavior exactly — including RFC divergences (permissive handshake
predicate, close-code quirks) — but refuses to copy shipped unsafety… RFC remains
the vocabulary authority for corpus expectations."*

Every one of sequences 1–49 cites that amendment by digest in its own rationale.
The adoption is not an accident anywhere in that range; it is executing an owner
ruling.

---

## 3. The cross, and the two traps

### Trap 1, first near-miss: the entire server-handshake leniency

`rust/ws-core/src/handshake/server.rs:7-13` declares, in the port's own voice,
that it strips sixteen checks:

> *"The stripped Codex checks — bare-LF and obs-fold byte policing, header-name
> tokens, duplicate headers, Host/Upgrade/Connection requirements, key
> base64/length validation, Content-Length/Transfer-Encoding/extension/subprotocol
> rejections, and the strict request-line grammar — are exactly the 16
> live-recorded RFC-reject-but-Java-accept divergences this slice must NOT
> reject."*

Set beside **US-011 AC1** — *"The server incrementally parses GET HTTP/1.1
requests and validates method/version, resource descriptor, Host presence,
Upgrade and Connection tokens, version 13, base64 16-byte key semantics, absent
excluded extensions, and configured byte/header limits"* — and **US-011 AC4** —
*"Java leniency cannot lower the RFC gate"* — this reads like F010 at twenty
times the scale: the port validates neither Host presence, nor the Upgrade and
Connection tokens, nor base64 16-byte key semantics. `accept_handshake_as_server`
(`server.rs:51-58`) checks the version and nothing else; `server.rs:180-186`
accepts any non-empty key, base64 or not, any length.

**I was wrong, and this is exactly F010's mirror error.** The amendment covers
it twice over: AC1's validation clause and AC4's leniency clause both *require
rejecting behavior which the pinned live-verified Java exhibits*, which is the
amendment's operative phrase verbatim; and the amendment's context names **"RFC
handshake validation gate"** as one of the five conflict families it was written
to settle. Records 1–16, 42 and 45–47 are that family, each citing the amendment
by digest. Filing this would have been an argument that sounds strong, is easy to
check, and is wrong — aimed at nineteen ledger records and an owner decision.

**Verdict: no conflict. US-011 AC1 and AC4 are amended, by text and by named
family, and the port complies with the amended form.**

### Trap 1, second near-miss: the mask-by-role leniency

**US-012 AC4** names one leniency specifically and says do not copy it: *"Java's
known unmasked-input leniency is classified as a quirk, not emulated."*

Ledger sequence 18 (`draft6455.framing.mask-by-role-acceptance`) is that
leniency, and the port emulates it. Its own test names say so:
`mask_direction_mismatches_are_accepted_toward_either_role` and
`mask_role_mismatch_seeds_are_accepted_not_rejected`. On its face this is F010's
twin: a targeted "do not copy this particular Java behaviour" clause, copied.

**Also cleared, and by the same two steps.** "not emulated" requires rejecting
behaviour Java exhibits, so the amendment's text reaches it; and the amendment's
context names **"mask/noncanonical-length rejection"** as the first of its five
families. Sequence 18 cites the amendment by digest.

**Verdict: no conflict. US-012 AC4's behavioural half is amended; its
classification half ("classified as a quirk") is satisfied — the quirk is
classified, at sequence 18.**

### And this is why the two near-misses matter more than a third finding would

US-011 AC4 and US-012 AC4 are the **same shape as US-011 AC2**: three targeted
"the port must not be Java-faithful here" clauses, all inside US-010..US-016,
all reached by the amendment's operative sentence. Two of the three are also
named explicitly in the amendment's list of five families. **US-011 AC2's
banner clause is the one that is not.** It is also the only one of the three that
is not RFC-strictness at all: RFC 6455 §4.2.2 permits additional header fields,
so forbidding a vendor banner is stricter than the RFC, not a restatement of it.
That asymmetry is the finding in §4.

### The rest of the cross, story by story

- **US-010 AC2/AC3, US-011 AC1/AC3, US-012 AC1/AC2/AC3, US-013 AC1/AC2,
  US-014 AC2, US-015 AC1/AC2/AC3, US-016 AC1/AC2/AC3** — every clause the port's
  adopted behaviour contradicts falls inside one of the amendment's five named
  families. Worked examples: US-015 AC3's *"payload caps"* against sequence 26's
  uncapped send-path control payloads → family "control payload caps"; US-015
  AC1's *"according to the configured automatic-response policy"* against
  sequence 25's never-auto-ponging core → family "automatic-pong policy";
  US-016 AC1's *"implement the RFC 6455 two-way handshake, echo/acknowledgment
  rules… legal codes"* against sequences 27–35 → family "RFC close-code table +
  echo matching"; US-012 AC3's *"noncanonical lengths, 64-bit high bit"* against
  sequences 17 and 19 → family "mask/noncanonical-length rejection".
  **No conflict.**
- **US-010 AC4** (*"added to the delta ledger rather than copied"*) — the port
  copies six client-handshake divergences (sequences 36–41) AND ledgers them. The
  "rather than copied" half is amended; the ledger half the amendment
  *reasserts* (*"Each Java-vs-RFC divergence MUST be recorded"*) and is
  satisfied. The GOAL-LOOP US-010 row already flagged this clause as *"worth
  reading beside F010"* and left it unaudited; **this sweep resolves it as no
  conflict.**
- **US-019 AC3** (*"every in-scope case is strict-pass"*) — 11 NON-STRICT cases
  are Java-faithful behaviour the literal clause forbids, and US-019 is OUTSIDE
  the amendment's range. Cleared by a separate owner decision:
  `us019-owner-decisions-2026-08-28-d.json` id `us019-ac3-strict-pass-reading`
  amends the strict-pass clause to per-case class agreement with the pinned Java
  baseline, keeping the reconciliation half literal. **No conflict.**
- **US-020 AC3** (three mismatch classes) — satisfied; sequences 50–58 carry
  `mismatch_class`, and 49 pre-vocabulary records are published as unclassified
  rather than back-filled.
- **US-020 AC2** (the rank order) — sequence 50 adopts a behaviour its own
  rationale calls RFC-divergent: *"RFC 6455 section 5.5.1 is DETERMINATE here…
  and shipped Java is on the other side of it."* I considered filing that as
  rank-four overriding rank-one. It does not hold: AC2 governs adjudication, and
  sequence 50 does not claim the RFC divergence resolved — it records it, names
  the clause, and classes it `java-quirk`, which is what US-020 AC3 asks for. The
  agreement between Java and Rust is disclosed, not used to close the question.
  **No conflict.**
- **US-002 AC5** (*"Java is never treated as normative when it conflicts with RFC
  6455"*) — the clause is unqualified, and the plane-wide normativity decision is
  its opposite in general form. But the clause sits in US-002, whose subject is
  the oracle custodian and whose first half is about the ledger; and the
  normativity decision's own carve-out — *"RFC remains the vocabulary authority
  for corpus expectations"* — is consistent with reading AC5 as governing
  adjudication rather than the port's emitted behaviour. **I do not file this as
  an instance**, and I flag instead that US-002 AC5 and US-020 AC2 are the two
  criteria that state the normativity RULE and that NEITHER is inside the
  amendment's US-010..US-016 range. That is a scope gap in the amendment, not a
  defect in any fix, and it is what lets this class recur.
- **US-018 AC5** (*"No TLS, proxy, reconnect, Android, async-runtime, extension,
  compression, or general public client/server API is added"*) — no adopted
  behaviour adds any. **No conflict.**
- **US-024 AC1/AC4** — US-024 is not started; nothing to cross.

### A criterion the port SATISFIES, arrived at from outside F010

**US-009 AC2** — *"ConnectionCore accepts immutable ConnectionConfig, Role,
TransportBytes, and LocalCommand and returns ordered TransportWrite,
SemanticEvent, ConnectionState, and TypedProtocolFailure values without opening
sockets, reading clocks, or invoking callbacks."*

Java reads the wall clock in `getServerTime` (`Draft_6455.java:818-824`). The
`Date` field is the one place DIV-06 could have imported that read into the core.
It did not: `accept_response(accept_key, connection, server_date_epoch_seconds)`
takes the instant as a parameter. Measured rather than read off the doc comment —
`grep -rn "Instant::now\|SystemTime\|std::time\|TcpStream\|std::net" rust/ws-core/src/`
returns **zero lines**, and `rust/ws-core/Cargo.toml` has an empty
`[dependencies]`.

Two things follow that F010's addendum could not say from inside AC2. First, the
clockless design is not merely a mitigation the owner may weigh — it is
compliance with **US-009 AC2, which is OUTSIDE the amendment's range and
therefore stands unamended**. Second, that makes the design load-bearing for
whichever way the owner rules: **if the ruling keeps `Date`, the injected-instant
seam must stay, because a core that read a clock to fill it would breach US-009
AC2 whatever US-011 AC2 says.** F010's addendum 1 was right to refuse the
determinism argument, and this is the criterion that was doing the work.

### Trap 2 — clauses that are SILENT, said as silence

Per the task's rule, these are recorded as "does not speak to", never as
"allows":

- **US-017 AC5** (*"Conformance and differential adapters invoke this same driver
  and core"*) **does not speak to** the two paths running the same symbols under
  different configuration. Sequence 57 records that split: the full-stack path
  uses `InboundFeedPolicy::OneFramePerTurn` and the oracle path keeps
  `WholeChunk`, producing different event/write ordering from the same bytes.
  AC5 constrains symbol identity, which holds.
- **US-020 AC1** (*"identical role, initial state, bytes, chunk boundaries, local
  actions, and limits"*) **does not speak to** the feed policy: it lists what
  must be identical across the Java and Rust legs of one differential, and the
  policy is not in that list and is not compared across the port's own two paths.
- **US-018 AC2** (*"clean shutdown, failed-connect, partial I/O, peer loss, slow
  reader/writer"*) **does not speak to** which endpoint closes the TCP
  connection.
- **US-009 AC4** (*"the core remains deterministic under arbitrary byte
  chunking"*) **does not speak to** chunk-boundary INVARIANCE. It asserts
  determinism, and I decline to read it as invariance; US-021 AC1 names
  *"chunk-boundary invariance"* separately, which is where that property lives
  and where it is already recorded as not met.
- **No AC in the child PRD speaks to** RFC 6455 §5.3's requirement that a
  masking key be unpredictable, which quirk Q28's deterministic
  `mask_key_seed` (`rust/ws-core/src/config.rs:241`, default 0) does not
  satisfy. Named for completeness and NOT filed: it is a divergence FROM Java,
  not an adoption OF Java, so it is outside this class by construction.

---

## 4. The one further instance, and the ruling F010 is actually owed

### Instance 1 (new) — US-018 AC1 and the role-gated transport close

**The criterion, verbatim** (`docs/prd-pack/07b-child-prd-us009-us019.md`,
US-018 AC1):

> "The client and server adapters own only socket accept/connect, partial
> read/write, write flushing, bounded I/O buffers, explicit timeout/EOF
> commands, process lifecycle, and report/testee routing; **handshake, framing,
> limits, and close semantics remain in ConnectionCore**."

and US-018 AC3:

> "A linkage test proves the adapters call the exact shipped core/driver symbols
> and **a seeded adapter-side parser or protocol branch fails the architecture
> gate**."

**The exact behaviour.** `rust/ws-testee/src/io_loop.rs:567-569`:

```rust
fn server_closes_transport(role: Role, state: ReadyState) -> bool {
    role == Role::Server && state == ReadyState::Closing
}
```

consulted at `:426` on the drained `Idle` path. A branch on protocol role and
protocol ready-state, deciding an externally observable close-handshake event —
which endpoint sends TCP FIN, and when — implemented in the adapter.

**What Java does.** `SocketChannelIOHelper.java:110-113` gates
`ws.closeConnection()` on `outQueue.isEmpty() && isFlushAndClose() && … getRole()
== Role.SERVER`; `batch(` has exactly one caller, `WebSocketServer.java:586`, so
"server write path only" is the complete call graph. The client has no
counterpart. Ledger sequence 50 carries the mapping operand by operand and its
disposition is `adopt-java` / `java-quirk`, including the half its own rationale
says RFC 6455 §5.5.1 does not permit.

**Why this is in F010's class.** The Java citation was verified exhaustively and
at source — the landing record re-read the pinned tree itself and checked the
call graph was complete rather than inferred. **No self-review record in this
repository mentions US-018**: before this file existed,
`grep -rn "US-018" drafts/self-review/` returned nothing, and the only hits now
are this record's own. The behaviour was checked against Java, against the RFC,
and against a parallel measurement; it was never checked against the acceptance
criterion of the story that owns the surface it landed on.

**And the crate contradicts itself, which is sharper than the absence of a
review.** I first wrote the sentence above as the whole of the evidence, then
checked the SOURCE rather than trusting the review tree — and US-018 AC1 is
cited twice inside `ws-testee`. Once for a different clause
(`io_loop.rs:17`, *"US-018 AC1: bounded I/O buffers"*), and once, at
`rust/ws-testee/src/server.rs:47-49`, for exactly this one:

> "Echo policy: every delivered text/binary message is re-sent through the
> bounded command handle. **Control and close behavior is deliberately NOT
> mirrored here — the core owns it (no adapter-side protocol, US-018 AC1).**"

So the rule is not merely unchecked — it is **stated as a rule in the same crate
that then departs from it.** One file of `ws-testee` declines to mirror close
behaviour and cites US-018 AC1 as its reason; another file of `ws-testee` mirrors
Java's close gate on a branch over `Role` and `ReadyState`. Whichever way the
placement is ruled, those two comments cannot both stand as written, and that is
true independently of the ruling.

**Why it is NARROWER than F010, stated plainly rather than inflated.** The
BEHAVIOUR is licensed: US-016's close clauses are inside the amendment, and the
plane-wide normativity decision covers mirroring Java's RFC divergences. Only
the PLACEMENT is in question, and there are two real arguments on the other
side. First, the port mirrors Java's own layering — Java's rule lives in its I/O
helper, not in `Draft_6455`, and the doc comment at `:565-566` says exactly that.
Second, ConnectionCore structurally cannot own this: US-009 AC2 forbids it to
open sockets, so it cannot close one either, and AC1's sibling terms
(handshake, framing, limits) are all things the core CAN do. A criterion that
required the core to own a decision it has no vocabulary to express would be
requiring a signal that does not exist rather than a relocation.

Note also that the ADJACENT placement question was already put to the owner and
ruled, which is why this one stands out for not having been:
`us017-c6-layer-split-owner-decision-2026-08-28.json` ruled *"PLACE THE REACTION
IN THE ADAPTER, NOT THE CORE"* for DIV-01's protocol-violation close — and the
architecture gate then pushed the frame COMPOSITION back into `ws-driver`
(`rust/ws-driver/src/lib.rs:1802-1811`: *"the `adapter-linkage` gate
(`cmd/rustgatectl`) forbids adapter sources from naming `ws_core::framing` or
`Draft6455` at all… an adapter that hand-rolls a frame is the thing the gate
exists to catch"*). So DIV-01's placement was checked twice, by an owner and by a
gate. `server_closes_transport` names neither symbol, so the gate does not see
it, and no owner decision covers it.

**Measured cost of each resolution. Nothing estimated; the source was patched,
run, and restored.**

Baseline at `4cf3f8f`: `cargo test -p ws-testee --all-targets` **exit 0**
(4 + 0 + 4 + 28 + 8 passing).

Variant — `server_closes_transport` neutralised to `false`, which is the floor
any relocation must keep passing.
`cargo test -p ws-testee --all-targets --no-fail-fast` **exit 101**, 5 failing:

- `io_loop::tests::only_a_closing_server_closes_the_transport_itself` (unit)
- `a_server_closes_the_tcp_connection_once_its_close_echo_has_drained`
- `a_server_in_closing_hangs_up_once_the_driver_has_taken_every_inbound_byte`
- `a_server_that_initiates_a_close_hangs_up_without_waiting_for_the_echo`
- `the_server_fixture_reaches_its_terminal_without_the_peer_ever_closing`

`a_client_does_not_close_the_tcp_connection_after_its_close_echo` **passes** in
the variant — the client half of the role gate is independent of the server half,
which the truth-table test alone could not establish.

Restored: `sha256sum -c` **OK**, `git status --porcelain -- rust/` **empty**.

So the two resolutions cost:

- **(a) The placement stands** — AC1 read as putting transport policy in the
  adapter, or amended to say so. **0 tests move.** The cost is that US-018 AC1's
  placement clause has one carve-out with no gate behind it, and the next
  adapter-side protocol branch has a precedent.
- **(b) AC1 governs as written** — the rule moves into `ws-driver` as a
  non-`poll` helper, exactly the shape `compose_violation_close` already is.
  **Behaviour-preserving, so those 5 tests should all still pass after the move**
  — the 5 above are the acceptance set for it, not a cost. The real cost is the
  one the C6 lane MEASURED: a core/driver placement is what moved 18 of 74
  public corpus cases and took scored-field disagreement with live Java from 0 to
  18. `compose_violation_close` shows the safe shape (nothing inside
  `ConnectionDriver::poll` calls it, so the oracle harness cannot see it, and
  that was measured rather than argued), but whether the transport-close rule
  can take that shape is unmeasured here and is implementation work, not sweep
  work. **I did not measure it and I do not claim it is free.**

I do not presuppose a ruling. (a) and (b) are both defensible and the
measurements above are what distinguishes them.

### Instance 0 (F010, corrected) — the ruling actually owed is not the one F010 states

F010 asks the owner to choose between "AC2 stands" and "amend AC2". **A general
amendment to US-010..US-016's acceptance criteria already exists, decided
2026-08-27, seven days before DIV-06 landed as `ddc148d`, and F010 does not cite
it** (`grep -c "JAVA_FAITHFUL_PLUS_SAFE\|us010-016-ac-amendment"` over
`F010-a-fix-that-a-story-criterion-forbids.md` returns **0**; its four "amend"
hits are all proposals for a FUTURE amendment). The same is true of
`div06-handshake-response-round-1.md`, the landing's own review round: **0**.

This does not overturn F010. It re-poses its question, more precisely:

- **Not** "should the owner amend AC2?" — that framing asks for a new decision
  and hides that a relevant one exists.
- **But** "does the standing amendment already reach AC2's banner clause?" Its
  operative sentence covers *"every AC clause of US-010..US-016 that requires
  rejecting, transforming, or augmenting behavior which the pinned live-verified
  Java… exhibits."* Java exhibits emitting `Date` and `Server`; AC2 requires the
  port not to. Whether requiring OMISSION is "transforming" is a genuine
  interpretive question and I do not answer it.
- **And the evidence cuts both ways, which is why it is the owner's.** FOR
  coverage: the operative sentence is written generally, and the two clauses of
  the same shape (US-011 AC4, US-012 AC4) are reached by it. AGAINST coverage:
  the amendment's stated context is a conflict with *RFC-strict* AC clauses and
  names five families, and the banner clause is in none of them and is not
  RFC-strict at all — RFC 6455 §4.2.2 requires only `Upgrade`, `Connection` and
  `Sec-WebSocket-Accept` and permits more, so "no vendor banner" is stricter than
  the RFC rather than a restatement of it. An amendment written to resolve
  "the ACs are stricter than Java" does not obviously reach a clause that is
  stricter than both.

**A new measurement that firms up F010's premise.** F010's evidence for what the
port emits is `ws-core` unit tests. At this head the banner reaches a real
socket: in the loopback suite (exit 0 above)
`the_servers_101_date_field_carries_a_live_clock_not_a_fixed_instant` and
`each_accepted_connection_stamps_its_own_date_not_the_fixtures` both pass, so the
adapter supplies a live clock per connection and the five-field head goes out on
the wire, not only through a fixture.

F010's addendum-2 cost table is not re-measured here and I make no claim it has
moved; `ws-core` is byte-identical to `4cf3f8f` in this worktree.

### Instance count, and the systemic finding behind both

**Nothing in this repository checks a fix, or a ledger record, against a story
criterion.** Sequence 58 says so from the inside: *"this ledger's authority model
has one normative pole (RFC 6455) plus three observation sources with no field
for a project criterion, so the conflict can only be stated here."* I confirmed
it from the outside: only four Go files reference `docs/prd-pack/` at all
(`internal/ac5class/register.go`, `internal/mutdenom/model.go`,
`internal/oraclerank/rank.go`, and the last as a doc comment), and every US-011
AC2 mention in Go code is prose inside
`internal/deltaledger/definitions_stale_port_corrections.go`. The US-020 AC2
mechanism that does exist (`internal/oraclerank`) cannot see either instance: its
handshake family scores accept/reject/incomplete VERDICTS, not the 101 response
field set, and its Autobahn family reads a run that predates both fixes. **So
this class is not merely undetected by accident — no gate in the tree is capable
of detecting it, and both instances were found by a human reading a PRD.**

---

## 5. What I did NOT sweep, and the ceiling on the negative

The negative result is: **within US-010..US-016, F010 is the unique instance**,
and outside it there is exactly one further instance, narrower. That is bounded
by the following, each a real limit rather than a hedge.

**What bounds it well.** The anti-Java-fidelity surface is provably small: the
`grep` in §1 is a whole-file mechanical scan of all three child-PRD parts for
every "must not be Java-faithful" formulation, and it returns six clauses. A
seventh cannot hide from that scan unless it avoids the word "Java" entirely
while still constraining Java fidelity, which I searched for by reading all 136
bullets and found no instance of.

**What bounds it badly, named individually.**

1. **The amendment's scope is read, not adjudicated.** My clearance of nineteen
   handshake records, sequence 18, and the US-010..US-016 close/control/framing
   families all rest on ONE reading of one sentence in one owner decision. If the
   owner reads "requires rejecting, transforming, or augmenting" more narrowly
   than I have, several of those clearances reopen at once — and the honest
   consequence is that the count of instances in this sweep is **not robust to a
   narrower reading of the amendment**. It is robust to a WIDER one, which would
   only clear F010 too.
2. **The master PRD was not swept.** I read the child PRD
   (`docs/prd-pack/07{a,b,c}`) in full and the metadata parts
   (`06a`/`06b`/`06c`) not at all, and the master stories
   (`02`–`05`) not at all. A criterion constraining port behaviour that lives in
   the master stories or the PRD metadata is outside this sweep entirely.
3. **The protected store was read only as committed bytes.** I read
   `evidence/governance/decisions/` with `VJWP_PROTECTED_STORE` exported. Two
   decisions cited in ledger rationales are named as living in the *workspace
   orchestrator* protected store, not this repository, and I could not open
   those: I verified the amendment's digest by the filename and sha256 the
   rationales quote, not by recomputation against the orchestrator's copy.
4. **No Autobahn, no benchmark, no AWS run.** So every claim about what the port
   does on the wire rests on the local suites plus the committed 518b77aa run.
   DIV-01's and DIV-02's closure is still *"fix landed, closure unconfirmed"*.
5. **One head, one platform.** Everything measured is `4cf3f8f` on Linux
   x86_64. US-018 AC2 names macOS arm64 as well; I ran nothing there.
6. **I did not re-measure F010's own cost table** or the DIV-05 ordering, and I
   did not touch `ws-core`.
7. **The 49 pre-vocabulary records were read as a class, not individually.** I
   read the rationales of sequences 18, 23, 25, 26, 27, 48, 49, 50, 51, 52, 54,
   55, 56, 57 and 58 in full, and sequences 1–16, 36–41 and 45–47 by subject and
   RFC anchor plus a sample of four rationales. A criterion conflict hiding in
   the prose of one of the ~30 rationales I did not read in full would have been
   missed.

**Corpus and denominators, unchanged.** 58 ledger records, 136 AC bullets, the
247-case pinned manifest, 74/74 public corpus, 49/49 handshake exam. Nothing was
re-baselined and `origin/codex/race-catchup` was not touched or read.

---

## 6. Owner actions, and the gates not triggered

No owner gate was triggered by this sweep. No AWS instance, no benchmark sample,
no Autobahn run.

0. **The two `ws-testee` comments about US-018 AC1 disagree with each other**
   (`server.rs:47-49` versus the gate at `io_loop.rs:567`). That needs fixing
   whichever way item 2 is ruled, and it is the one item here that is not
   waiting on a decision.
1. **Rule on US-011 AC2 versus the standing amendment.** The question is
   *"does `us010-016-ac-amendment-owner-decision-2026-08-27.json` already reach
   AC2's `no Java-specific Date or Server banner` clause?"* — YES leaves DIV-06
   as it is and needs sequence 58 superseded with `adopt-java`; NO leaves F010's
   two options intact with its measured costs (4 tests for `Server`, 3 for
   `Date`). Either way the clockless seam stays, per US-009 AC2.
2. **Rule on US-018 AC1's placement clause** for `server_closes_transport`:
   (a) placement stands, 0 tests move; (b) relocate to `ws-driver`, with the 5
   tests above as its acceptance set and the corpus-invisibility of the new seam
   to be MEASURED, not argued, as the C6 lane's hard stop requires.
3. **The Autobahn re-run**, which
   `us017-c6-layer-split-owner-decision-2026-08-28.json` requirement 3 asks for
   in as many words (*"Re-run Autobahn to MEASURE the improvement rather than
   reasoning about it"*) and which DIV-01's and DIV-02's per-case acceptance sets
   are both waiting on.
4. **Consider whether the amendment's silence on US-002 AC5 and US-020 AC2 is
   intended.** Those are the two criteria that state the normativity rule; both
   sit outside the amended range while the plane's stance is their opposite in
   general form.

## 7. Gates

- `cargo test -p ws-testee --all-targets` at `4cf3f8f`: **exit 0**.
- `cargo test -p ws-testee --all-targets --no-fail-fast`, variant applied:
  **exit 101**, 5 named failures.
- `sha256sum -c` after restore: **OK**. `git status --porcelain -- rust/`:
  **empty output**.
- `go run ./cmd/recordguardctl precondition drafts/self-review/story-criterion-sweep.md`:
  recorded in the landing note below.
- `make -C rust gates` with `VJWP_PROTECTED_STORE` exported: recorded in the
  landing note below.

## 8. Readings behind this sweep

- `docs/prd-pack/07a-child-prd-header-index-us001-008.md`,
  `07b-child-prd-us009-us019.md`, `07c-child-prd-us020-us027.md` — all 136 AC
  bullets read.
- `drafts/self-review/findings/F010-a-fix-that-a-story-criterion-forbids.md` —
  the finding and both addenda.
- `evidence/java/behavior-delta-ledger.json` — all 58 records by subject and
  disposition; 15 rationales in full.
- `evidence/governance/decisions/us010-016-ac-amendment-owner-decision-2026-08-27.json`,
  `us009-us008-owner-decisions-2026-08-27.json`,
  `us017-c6-layer-split-owner-decision-2026-08-28.json`,
  `us019-owner-decisions-2026-08-28-d.json`.
- `internal/deltaledger/definitions.go:1-30`,
  `internal/divergencesweep/classes.go:93-256`, `internal/oraclerank/rank.go`,
  `internal/oraclerank/census.go`.
- `rust/ws-core/src/handshake/server.rs`, `rust/ws-core/src/config.rs`,
  `rust/ws-core/Cargo.toml`, `rust/ws-driver/src/lib.rs` (feed policy,
  `compose_violation_close`), `rust/ws-testee/src/io_loop.rs`.
- `.claude/GOAL-LOOP.md` rows US-009 through US-020 and both criteria-audit
  passes — which is how I know US-012 through US-016 had never been audited
  against their criteria, and that US-011's AC1/AC3/AC4/AC5 and US-010's
  AC1/AC2/AC3/AC5 had not either.
