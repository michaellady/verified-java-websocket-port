# F010 — DIV-06's fix makes the port emit exactly what US-011 AC2 forbids, and the ledger record still describes the pre-fix port
phase: criteria audit (US-010/US-011, first pass)   step: n/a   date: 2026-09-03T12:27Z

what happened: auditing US-010 and US-011 against the child PRD for the first time — they had never been audited — turned up a direct contradiction between a change I reviewed and landed today and an acceptance criterion that was in the tree the whole time.

**US-011 AC2** (`docs/prd-pack/07b-child-prd-us009-us019.md`): *"A valid request emits a deterministic 101 response with the exact Sec-WebSocket-Accept, required headers, **no Java-specific Date or Server banner**, and a normalized semantic handshake event."*

**The shipped port, after DIV-06 landed as `ddc148d`**: `rust/ws-core/src/handshake/server.rs:264` writes `\r\nDate: ` and `:268` writes `\r\nServer: TooTallNate Java-WebSocket\r\n`, and `handshake_server_response.rs` asserts all five field names in Java's TreeMap order. The port now emits precisely the two fields the criterion names as forbidden, and a test pins that it does.

**And ledger sequence 55 is stale in the same direction.** Its rationale opens *"the port's response OMITS the Server and Date fields shipped Java adds"* — the pre-fix state — while its disposition is `unresolved` / `underspecified-behavior` with an owner ruling named as the precondition. So the chain records an open question, the criterion records an answer, and the port shipped the opposite answer without either being updated.

what it cost: nothing on the wire yet — this is a laboratory and no acceptance is claimed. What it cost is trust in the landing: I reviewed DIV-06 carefully, re-read every Java citation at source, verified the anti-circularity mask was not vacuous, and traced the `Connection` echo that no sweep could have found. **I never checked the change against the acceptance criteria of the story it belongs to.**

where the deciding moment was: when the review asked "does this match shipped Java?" and never asked "does this story permit matching shipped Java here?". Java fidelity is the method, not the goal — the program's own framing is *parity without preserving Java defects*, and a vendor `Server` banner is the textbook example of a defect not to preserve. The criteria audit had covered US-017 through US-027 and never reached US-010/US-011, so the one document that would have caught it was the one nobody read.

**The two halves of DIV-06 are not the same case, and the remedy must not treat them alike.** The `Connection` echo fix (Java echoes the request's value; the port hard-coded `Upgrade`) is untouched by AC2, was the genuinely hidden divergence, and should stand. Only the `Server`/`Date` half conflicts.

evidence: `grep -n "Server:\|Date:" rust/ws-core/src/handshake/server.rs` shows both writes; `handshake_server_response.rs:109-115` pins the five names; US-011 AC2 as quoted; ledger sequence 55's rationale as quoted; DIV-06's landing commit `ddc148d`.

bin: a NEW class beside the collection. Not existence standing in for identity, and not its mirror — this is **fidelity standing in for correctness**: a change verified exhaustively against the source it imitates, and never against the specification that governs whether imitation is wanted there. Every citation in that landing was right. The question they answered was the wrong one. The portable rule: before landing a fidelity fix, read the acceptance criterion of the story that owns the surface, and check that the criterion permits the fidelity — a Java citation is not an authority for whether to follow Java.

**OWNER DECISION REQUIRED — three options, and this loop should not choose between them:**
(a) **US-011 AC2 governs**: revert the `Server`/`Date` half, keep the `Connection` echo, and supersede ledger sequence 55 with a record whose disposition is `intentional-correction` — the port deliberately declines a Java banner.
(b) **The adoption governs**: amend US-011 AC2, and supersede sequence 55 with `adopt-java` / `java-quirk` plus a rationale for why a vendor banner is worth adopting.
(c) **Split**: keep `Date` (arguably an HTTP-conventional field) and drop the `Server` banner, with the ledger recording each separately.
Whichever is chosen, sequence 55's rationale is stale as written and needs superseding — it describes a port that no longer exists, which is the same defect the DIV-05 continuation found in sequence 34 today.

---

## Addendum, 2026-09-03: the two halves are not equally arguable

I re-read AC2 in full context (`docs/prd-pack/07b-child-prd-us009-us019.md:33`,
the second of five criteria) and read the emission at source rather than from
this finding's own summary. Two corrections to how the decision was framed, both
of which make the owner's job smaller.

### 1. The `Server` banner needs no ruling on WHETHER it violates AC2

`rust/ws-core/src/handshake/server.rs:281` writes:

```rust
response.extend_from_slice(b"\r\nServer: TooTallNate Java-WebSocket\r\n");
```

AC2's phrase is "no Java-specific Date or Server banner". Parse it any of the
three available ways — `no [Java-specific Date] or [Server banner]`, `no
Java-specific [Date or Server banner]`, or `no [Java-specific Date] or
[Java-specific Server banner]` — and a header whose literal value names the Java
vendor library is forbidden under all of them. There is no reading of that
clause under which `Server: TooTallNate Java-WebSocket` is permitted.

So option (b) as originally written — "the adoption governs, amend AC2" — is not
an interpretive choice about what AC2 means. It is a request to CHANGE AC2. That
is still a legitimate thing for the owner to decide, but it should be presented
as an amendment, not as a reading. Framing it as a reading invites agreement to
something narrower than what is actually being agreed to.

### 2. I nearly stacked a weak argument onto a strong one

AC2 also says the 101 response must be **deterministic**, and a `Date` header is
the textbook example of a field that is not. I was about to add that as a second,
independent count against the `Date` half. It does not hold, and the reason is a
deliberate piece of engineering in the very change this finding is about.

`accept_response` does not read a clock:

```rust
fn accept_response(accept_key: &str, connection: &str, server_date_epoch_seconds: i64) -> Vec<u8>
```

The instant is a parameter, injected at `ServerHandshake::new`. The doc comment
at `server.rs:132-146` says so explicitly, and gives the reason: keeping the core
clockless is what stops it from emitting "a plausible-looking `Date` that no
clock produced". `java_server_time` is a pure function of an epoch second, and
its expectations are pinned from the JDK formatter's own output rather than
written by hand. The author also checked the one thing that would have made the
function impure in disguise — that `Locale.US` and the explicit GMT zone make
the rendering independent of the host timezone, verified against the pinned JDK
under two different `-Duser.timezone` settings.

So the response IS a deterministic function of its inputs. The wire bytes vary
with the clock the CALLER passes, which is a different claim and a much weaker
one. Presenting the determinism clause as an independent violation would have
been an argument that sounds strong, is easy to check, and is wrong — and it
would have been aimed at the most careful part of the change.

This matters beyond the drafting. F010's own thesis is that DIV-06 was verified
against the wrong authority. The mirror-image error is available to me here: to
condemn it against a clause it satisfies, because condemning is now the expected
direction. One bad reading is not corrected by another in the opposite
direction.

### What the owner actually has to decide

Narrower than three options:

- **`Server: TooTallNate Java-WebSocket`** — violates AC2 under every reading.
  The only question is remove-it (AC2 stands) or amend-AC2-to-permit-a-vendor-
  banner. No interpretive question remains.
- **`Date`** — violates the natural reading of "Java-specific ... Date", since
  RFC 6455 §4.2.2 requires only `Upgrade`, `Connection` and
  `Sec-WebSocket-Accept`, and Java-WebSocket adds both of these. But it is NOT
  independently condemned by the determinism clause, and the clockless design is
  a genuine mitigation the owner should weigh rather than a loophole.
- **The `Connection` echo half of DIV-06 is untouched by AC2** and should stand.
  That was true as originally filed and re-reading has not changed it.

### Readings behind this addendum

- `docs/prd-pack/07b-child-prd-us009-us019.md:33` — AC2, quoted verbatim above
  and at the head of this finding, read in the context of all five criteria.
- `rust/ws-core/src/handshake/server.rs:277,:281` — the two `extend_from_slice`
  calls, read at source.
- `rust/ws-core/src/handshake/server.rs` `accept_response` signature and the
  `java_server_time` doc block — the clockless design and its stated reason.
- Still not run, and still an owner gate: the Autobahn re-run that would show
  whether either field moves a conformance case.

## Addendum 2, 2026-09-03: what each removal actually costs, measured

The addendum above narrowed WHAT the owner must decide. This one supplies the
other half they need to decide it: what each option costs. No owner gate was
triggered — this is the local suite only, and the Autobahn re-run that would
show whether either field moves a conformance case is still not run.

Method: each field removed from `accept_response` one at a time, `cargo test -p
ws-core --all-targets` run against each variant, the source restored
byte-identically after each (`diff -q`, clean).

Baseline, unmodified: exit 0, all suites green (18 + 14 + 9 + 28 + 4 passing).

### Variant A — remove `Server: TooTallNate Java-WebSocket`

`cargo test -p ws-core --all-targets` exit 101, 5 failing:

- `the_server_field_carries_javas_literal_and_upgrade_is_lowercase`
- `the_101_response_carries_javas_five_field_names_in_javas_order`
- `the_101_response_is_byte_exact_against_the_pinned_jars_own_output`
- `response_field_names_are_javas_constants_not_the_requests_casing`
- `the_connection_field_echoes_the_requests_value_rather_than_a_literal`

### Variant B — remove `Date`

`cargo test -p ws-core --all-targets` exit 101, 4 failing — the same list minus
the `Server`-specific one:

- `the_101_response_carries_javas_five_field_names_in_javas_order`
- `the_101_response_is_byte_exact_against_the_pinned_jars_own_output`
- `response_field_names_are_javas_constants_not_the_requests_casing`
- `the_connection_field_echoes_the_requests_value_rather_than_a_literal`

### The last entry in both lists is misleading, and it is the one that matters

`the_connection_field_echoes_the_requests_value_rather_than_a_literal` is the
test for the DIV-06 half that the addendum above establishes AC2 does NOT touch
and that should stand. Reading these lists naively says: removing the banner
breaks the part we agreed to keep. **That is not what happens.**

That test's three echo assertions are all about `Connection`. Its FOURTH and
final assertion is not:

```rust
assert_eq!(
    field_names(&head).len(),
    5,
    "the field is present-but-empty, so the count stays 5: {head:?}"
);
```

A field-COUNT assertion, riding inside a test named for the Connection echo.
Removing any field drops the count to 4 and fails it, no matter which field went.

Isolated rather than argued: with that one assertion neutralised and the `Server`
banner still removed, the failing set is the other four and
`the_connection_field_echoes_…` PASSES. Both files restored byte-identically
afterwards.

**So the Connection echo is unaffected by either removal.** The addendum above
reached that conclusion by reading AC2; this reaches it by measurement, and the
two agree.

### What this means for the decision

- Removing `Server` costs **4** tests, every one of them a DIV-06 fidelity
  assertion about the banner or the five-field set. Nothing else in `ws-core`
  moves.
- Removing `Date` costs **3**, the same set minus the `Server`-specific one.
- The load-bearing casualty in both cases is
  `the_101_response_is_byte_exact_against_the_pinned_jars_own_output`. That test
  is the whole point of DIV-06, and no option preserves it except leaving the
  response as it is. The owner is choosing between byte-exactness against the
  pinned jar and AC2 as written; the other failures are consequences of that one
  choice, not independent costs.
- The Connection echo survives every option and needs no decision.

### A test-hygiene point worth fixing regardless of the ruling

A count assertion inside a test named for a different property destroys
localisation: it makes the test fail for a reason its name disclaims, and it put
a misleading row into the very table an owner would use to weigh this decision.
Whatever is decided about the banner, that assertion belongs in
`the_101_response_carries_javas_five_field_names_in_javas_order`, which already
exists and is already named for exactly it.

### Readings behind this addendum

- `rust/ws-core/src/handshake/server.rs:270-283` — `accept_response`, the two
  removals applied at source.
- `rust/ws-core/tests/handshake_server_response.rs:195-236` — the Connection
  echo test, including the trailing count assertion at :231-235.
- `rust/ws-core/tests/handshake_server_response.rs:71-78` — `response_head`,
  checked and cleared: it asserts nothing about the field set, so the coupling
  is the count assertion alone and not the shared helper.
