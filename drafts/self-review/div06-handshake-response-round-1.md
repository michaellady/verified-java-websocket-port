# div06-handshake-response — self-review round 1

- Written 2026-09-02T20:02:24Z (`date -u`).
- Branch `claude/div06-handshake-response`, based on mainline
  `claude/feature/verified-java-websocket-port` at `57e881c`.
- Subject of the round: `rust/ws-core/src/handshake/server.rs`,
  `rust/ws-core/src/config.rs`, `rust/ws-core/src/connection.rs`,
  `rust/ws-testee/src/server.rs`,
  `rust/ws-oracle-harness/src/handshake_adapter.rs`,
  `rust/ws-core/tests/handshake_server_response.rs`,
  `rust/ws-testee/tests/loopback.rs`,
  `internal/divergencesweep/sweep_test.go`,
  `drafts/ledger-proposals/div06-handshake-response.json`.

Every exit code below was read from the process, never through a pipe.

## 1. What shipped Java actually does, read first-hand

**The tree was verified before it was trusted.**
`.quarantine/java-websocket-source-archive.tar.gz` re-digests to
`f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4`, equal to
`evidence/intake/source-pins.json`. Re-extracting it and running `diff -r`
against `.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/`
returned **exit 0 with zero lines of output**, so the tree read below is the
tree the pin names.

**AUTHORITY LABEL.** Everything in this section is a **source citation** into
that tree, corroborated by an **offline computation over the pinned jar**.
Neither is a live socket observation. No Java server was started for this work;
this repository's `java-oracle` is a JSONL request/response oracle and never
opens a server socket.

### `postProcessHandshakeResponseAsServer`, `Draft_6455.java:431-452`

It writes **five** fields, into a `HandshakeImpl1Server` that starts EMPTY
(`WebSocketAdapter.java:53-56` returns `new HandshakeImpl1Server()`):

| Java line | field | value |
|---|---|---|
| `:434` | `Upgrade` | the literal `websocket` |
| `:435-436` | `Connection` | **`request.getFieldValue(CONNECTION)` — the REQUEST's value, ECHOED**, with the comment `// to respond to a Connection keep alives` |
| `:441` | `Sec-WebSocket-Accept` | `generateFinalKey(seckey)` |
| `:449` | `Server` | the literal `TooTallNate Java-WebSocket` |
| `:450` | `Date` | `getServerTime()` — a wall-clock read (`:818-824`) |

`:437-440` throws `InvalidHandshakeException` on a missing or empty key before
any of `:441` onward runs. `:442-444` and `:445-447` add
`Sec-WebSocket-Extensions` and `Sec-WebSocket-Protocol` only when non-empty;
under `DefaultExtension` (`extensions/DefaultExtension.java:76-78` returns
`""`) and the default protocol both are empty, so neither reaches the wire, and
this port configures neither. `:448` sets the status MESSAGE
`Web Socket Protocol Handshake`, which `Draft.java:270` renders into the status
line — it is not a field.

### What determines header ordering on the wire

Not insertion order. `HandshakedataImpl1.java:50` stores fields in
`new TreeMap<>(String.CASE_INSENSITIVE_ORDER)`; `iterateHttpFields` (`:55-57`)
returns that key set's iterator; `Draft.createHandshake`
(`drafts/Draft.java:275-283`) writes `fieldname + ": " + fieldvalue + "\r\n"`
in exactly that iteration order. The wire order is therefore **case-insensitive
alphabetical**:

    Connection, Date, Sec-WebSocket-Accept, Server, Upgrade

The response's field NAMES are Java's own constants (`Draft_6455.java:96-106`),
so the request's casing never reaches the response.

### `getServerTime`, `Draft_6455.java:818-824`

`new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US)` with
`TimeZone.getTimeZone("GMT")`, formatting `Calendar.getInstance().getTime()`.
The only non-determinism is the `Calendar.getInstance()` clock read.

### The offline corroboration

A program (`Ground.java`, source in this round's scratchpad and reproduced
below) drives the same three calls `WebSocketImpl.java:300-301` makes —
`Draft.translateHandshakeHttp`, `postProcessHandshakeResponseAsServer`,
`Draft.createHandshake` — against the pinned `Java-WebSocket-1.6.0.jar` under
the pinned JDK `17.0.19+10`, and prints the resulting bytes. `javac` exit 0,
`java` exit 0. Output (`\r\n` rendered):

| request | response bytes |
|---|---|
| the recorded Autobahn suite request | `HTTP/1.1 101 Web Socket Protocol Handshake\r\nConnection: Upgrade\r\nDate: …\r\nSec-WebSocket-Accept: Hq135RN2s62Ig7vP5+0RjcM2Ies=\r\nServer: TooTallNate Java-WebSocket\r\nUpgrade: websocket\r\n\r\n` |
| RFC 6455 sample key | `…Connection: Upgrade\r\nDate: …\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nServer: …\r\nUpgrade: websocket\r\n\r\n` |
| `Connection: keep-alive, Upgrade` | `Connection: keep-alive, Upgrade` — **echoed** |
| duplicate `Connection: Upgrade` + `Connection: close` | `Connection: Upgrade; close` — joined with `"; "` per `Draft.java:120-125`, then echoed |
| **no** `Connection` header at all | `Connection: ` — the field is PRESENT with an EMPTY value |
| lowercase `connection:` in the request | `Connection:` in the response — Java's constant |

**This offline computation is bound to the one socket observation that
exists.** For the byte-exact request the Autobahn suite sent in the recorded
native run it reproduces `Sec-WebSocket-Accept: Hq135RN2s62Ig7vP5+0RjcM2Ies=`,
the same value that run's `httpResponse` carries
(`evidence/autobahn/native-x86_64-provenance/java/fuzzingclient-run1/cases/verified_java_websocket_port_1_6_0_case_10_1_1.json`).
That recorded response also shows the same five fields in the same order.

The same program printed `getServerTime()`'s format at 23 fixed instants. Two
of them are the epochs that render the two `Date` values the recorded run
observed: `1787943099` → `Fri, 28 Aug 2026 18:51:39 GMT` and `1787943111` →
`Fri, 28 Aug 2026 18:51:51 GMT`. The whole table was produced twice, under
`-Duser.timezone=UTC` and under `-Duser.timezone=Asia/Kolkata`; `diff` returned
**exit 0**, so the format depends on the instant alone.

### What the 3-of-5 comment had missed

`accept_response`'s doc comment read
`Upgrade/Connection/Sec-WebSocket-Accept per postProcessHandshakeResponseAsServer`.
The cited method writes five fields. The citation was true of the method's
*existence* and false of its *content* — "existence standing in for identity".

Reading the method myself turned up a **second** instance in the same file,
which the sweep had not flagged: `ServerHandshakeOutcome::Accept`'s doc said
Java `appends non-deterministic Date and Server fields at the I/O shell`. Wrong
twice over — `Server` is a fixed literal and not non-deterministic, and NEITHER
field is added at an I/O shell; both are written by
`postProcessHandshakeResponseAsServer`, the very method the file cites three
lines earlier. The doc had relocated the two missing fields to a layer where
they would be somebody else's problem.

And it turned up a **third divergence the sweep did not name and the recorded
run could not have caught**: the port hard-coded `Connection: Upgrade` where
`Draft_6455.java:435-436` echoes the request's value. The Autobahn suite sends
exactly `Connection: Upgrade` on all 247 cases, so the echo and the hard-code
are byte-identical in every case measured. The port's value looked right
because the input made it right — the same defect shape DIV-06 itself was
reported as.

## 2. The RED reading

Taken against **unmodified mainline source**, with a probe compiled against the
then-current API (`ServerHandshake::new(limits)`). `cargo test -p ws-core
--test div06_red_probe` → **exit 101**, 0 passed, 2 failed:

```
DIV-06: shipped Java's 101 response carries ["Connection", "Date",
"Sec-WebSocket-Accept", "Server", "Upgrade"] — five fields sorted by
String.CASE_INSENSITIVE_ORDER (Draft_6455.java:431-452 writes them,
HandshakedataImpl1.java:50 sorts them, Draft.java:275-283 writes them out).
The port produced ["Upgrade", "Connection", "Sec-WebSocket-Accept"]: it omits
Server and Date and does not sort.
  left: ["Upgrade", "Connection", "Sec-WebSocket-Accept"]
 right: ["Connection", "Date", "Sec-WebSocket-Accept", "Server", "Upgrade"]
```

```
DIV-06 (unrecorded sub-case): Draft_6455.java:435-436 is
response.put(CONNECTION, request.getFieldValue(CONNECTION)) — the value is
ECHOED from the request. The pinned jar answers this request with
`Connection: keep-alive, Upgrade`. The port wrote:
"HTTP/1.1 101 Web Socket Protocol Handshake\r\nUpgrade: websocket\r\n
Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n
\r\n" — it hard-codes `Connection: Upgrade`, which the recorded Autobahn run
could never catch because the suite always sends exactly `Connection: Upgrade`.
```

**Disclosure about the shape of this reading.** The permanent tests need the
fixed API (the instant is now a constructor argument), so they cannot be run
against unfixed source; the probe above is what was run there, and it was then
deleted in favour of `rust/ws-core/tests/handshake_server_response.rs`, which
contains the same two assertions plus byte-exactness. That the permanent tests
can fail is established by the deletion attacks in section 5, not by this
reading. A reader should treat section 5 as the load-bearing evidence and this
section as the demonstration that the defect was real in mainline before the
change.

## 3. The fix

- `rust/ws-core/src/handshake/server.rs` — `accept_response` writes all five
  fields in `String.CASE_INSENSITIVE_ORDER` and echoes the request's
  `Connection` value; its doc comment is now a field-by-field table with a Java
  line number per field, a separate paragraph citing the TreeMap that fixes
  wire order, and a statement of which two conditional fields are absent and
  why. `java_server_time` is a new pure function reproducing
  `getServerTime`'s format.
- `rust/ws-core/src/config.rs` — `ConnectionConfig` gains
  `server_date_epoch_seconds` with a builder setter and an infallible
  `with_server_date_epoch_seconds` on the built value.
- `rust/ws-core/src/connection.rs` — the server machine is built with the
  configured instant.
- `rust/ws-testee/src/server.rs` — **the one clock read**, per accepted
  connection.
- `rust/ws-oracle-harness/src/handshake_adapter.rs` — a fixed instant, with the
  reason recorded at the use site: that oracle scores the accept/reject
  verdict, the reject channel, the close code and the accept value, and
  discards the response head, so a clock there would put an irreproducible
  value in its transcripts that nothing compares.

**The Sans-I/O contract is kept.** `ws-core` is dependency-free and clockless
by contract (`rust/ws-core/Cargo.toml`: *no sockets, no clocks, no callbacks*).
The core owns the FORMAT, which is Java behaviour and belongs in the port; the
owner supplies the INSTANT. This is the seam `mask_key_seed` already uses for
the port's only other non-deterministic input. There is deliberately **no**
clockless constructor for `ServerHandshake` — a default instant would emit a
plausible-looking `Date` that no clock produced.

## 4. The `Date` normalization decision

**`Date` cannot be byte-reproducible, and it is NOT normalized away.**

It is a clock read by construction. It is not merely theoretical: the recorded
native run shows **nine distinct `Date` values across the 247 Java server
cases**, so the field genuinely varies within a single run of a single build.

A differential that normalized it — dropped the field, or rewrote both sides to
a constant — would erase a real difference. That is exactly the DIV-02 failure
mode. So the field is **split along the line where determinism actually
falls**:

- **The FORMAT does not vary, and is pinned byte-for-byte.** 22 instants in
  `rust/ws-core/tests/handshake_server_response.rs`, every expectation a string
  *printed by the pinned JDK* evaluating the same `SimpleDateFormat` expression
  `getServerTime` builds — not derived by hand. It includes both leap-day
  boundaries either side of 2020-02-29, the 2038 and 2106 rollovers, epoch 0,
  two negative epochs, and the two instants the recorded run observed.
- **The INSTANT does vary, and is checked as a property.**
  `rust/ws-testee/tests/loopback.rs::the_servers_101_date_field_carries_a_live_clock_not_a_fixed_instant`
  brackets the handshake with two wall-clock readings and requires the emitted
  `Date` to be some instant inside that interval. It is a **wall-clock window,
  never an iteration count** (finding F005).
- **And the clock must be read in the right place.**
  `each_accepted_connection_stamps_its_own_date_not_the_fixtures` serves two
  connections from ONE `ServerFixture` across a second boundary and requires
  the two `Date` values to differ. Without it, reading the clock once per
  fixture would pass every other check and still be unfaithful, because Java
  reads its clock inside the per-handshake call. Attack A7 confirms this test
  is not redundant: it fails alone, with the other 25 loopback tests passing.

**What no gate should do.** No byte-equality digest over a 101 response head
may include the `Date` value. Nothing in this repository currently digests that
head — the corpus differential and handshake exam both score the accept/reject
verdict and the `Sec-WebSocket-Accept` value, and the Autobahn sweep's
`subject_handshake_header_names` dimension compares field NAMES in order, which
is exactly the deterministic part. So no existing gate needed changing. That is
recorded here and in the closure draft so a future gate does not quietly add
one.

## 5. Deletion attacks

Method: back up the subject, apply ONE mutation that removes the thing a check
protects, run the test that names it, read the exit code and failure text,
restore, confirm green. Scripts: `attacks.py` and `attacks2.py` in this round's
scratchpad. Baseline before and after: `cargo test --workspace --all-targets
--all-features` exit 0; `go test ./internal/divergencesweep/` exit 0.

| # | mutation | test | exit | what it said |
|---|---|---|---|---|
| A1 | `accept_response` stops writing `Server` and `Date` (the original DIV-06 defect) | `handshake_server_response` | 101 | field-names, byte-exact and lowercase-name tests all fail; `DIV-06: the port's 101 head must equal, byte for byte, what the pinned Java-WebSocket 1.6.0 jar produced offline…` |
| A2 | `accept_response` hard-codes `Connection: Upgrade` again | `…::the_connection_field_echoes_the_requests_value_rather_than_a_literal` | 101 | `Draft_6455.java:435-436 echoes the request's Connection value…; the pinned jar answers this request with 'Connection: keep-alive, Upgrade'. The port wrote: …` (7 passed, 1 failed) |
| A3 | the five fields emitted in INSERTION order, not sorted order | `handshake_server_response` | 101 | `…The port produced ["Connection", "Date", "Sec-WebSocke…` |
| A4 | `java_server_time` drops the day's zero padding (`dd` → `d`) | `…::the_date_field_format_matches_the_pinned_jdks_simpledateformat` | 101 | `getServerTime (Draft_6455.java:818-824) on the pinned JDK prints "Thu, 01 Jan 1970 00:00:00 GMT" at epoch second 0` |
| A5 | `java_server_time` uses truncating division, so pre-1970 instants land on the wrong day | same | 101 | `…prints "Wed, 31 Dec 1969 23:59:59 GMT" at epoch second -1` |
| A6 | the `ws-testee` adapter stops reading the clock (fixed instant 0) | `loopback` | 101 | `Got "Thu, 01 Jan 1970 00:00:00 GMT", which is not any instant in the window [1788378365, 1788378365] this handshake ran in…` (2 failed) |
| A7 | the adapter reads the clock ONCE PER FIXTURE instead of per accept | `…::each_accepted_connection_stamps_its_own_date_not_the_fixtures` | 101 | `both connections stamped "Wed, 02 Sep 2026 19:46:08 GMT": the clock is being read once per fixture…` (**25 passed, 1 failed** — this test is not redundant) |
| A8 | the DIV-06 closure record is deleted | `TestDIV06IsClosedInThePortSourceItNames` | 1 | `the port site DIV-06 names has been fixed but drafts/ledger-proposals/div06-handshake-response.json does not exist…` |
| B1 | port site stops writing `Server` and `Date` | `TestDIV06IsClosedInThePortSourceItNames` | 1 | `accept_response no longer writes a Server field: … This is a regression, not a new finding.` |
| B2 | port site emits the five fields in INSERTION order | same | 1 | `accept_response writes Upgrade out of order: shipped Java emits Connection, Date, Sec-WebSocket-Accept, Server, Upgrade — case-insensitive alphabetical…` |
| B3 | port site hard-codes `Connection: Upgrade` again | same | 1 | `accept_response hard-codes Connection: Upgrade again. … No case in the recorded run can catch this, which is why it is checked here.` |
| B4 | port site emptied of its status line, five field writes kept | same | 1 | `accept_response no longer writes the 101 status line, so this check is no longer reading what it thinks it is` — the self-guard, not the field checks, is what fires |

Every check added or rewritten in this round can be made to fail. All mutations
were restored; `git status` after the round shows only the intended changes.

## 6. The tripwire, turned around rather than deleted

`internal/divergencesweep`'s `TestDIV06IsStillTrueOfThePortSourceItNames` was
written to FAIL when the port was fixed. It fired, as expected. It is now
`TestDIV06IsClosedInThePortSourceItNames` and asserts the **closure**: all five
fields present, in Java's case-insensitive alphabetical order (positions
strictly increasing in the source), the `Connection` value not a literal, the
status line still there as a self-guard, and the closure recorded. Attacks
A8/B1-B4 show each of those four branches can fail.

**`evidence/java/observed-close-divergences.json` is NOT edited.** It is a
measurement of one run against one build (`subject_commit 518b77aa`), and that
measurement stays true of that build. Editing it to say the divergence is gone
would be falsifying a measurement. The fact that mainline has moved past it is
carried by the rewritten test and by
`drafts/ledger-proposals/div06-handshake-response.json`.

## 7. Readings after the change

Re-run because `rust/ws-core/src` and `rust/ws-testee/src` changed. The public
and handshake tiers were regenerated from the committed public seed with a
**throwaway 32-byte hex** protected-root secret, which neither tier consumes.
No hidden or sealed tier was generated or scored. **No Autobahn run was
executed** (owner gate), and no AWS or benchmark gate was touched.

| reading | value | exit |
|---|---|---|
| handshake request digest | `sha256:e00d968f0ae623dd75a09842ad435642c0dca53ee5e9f9ef654ce26c1f814c49` — equal to the value the batch-B receipt and the server-close-parity draft record. **No corpus shift.** | — |
| corpus differential, port, public tier | **74/74**, 0 failed, 0 missing, 0 unmatched | 0 |
| handshake exam, port, runtime neutralised | **49/49**, **16** documented divergences | 0 |
| corpus differential, live pinned Java, public tier | **74/74** | 0 |
| handshake exam, live pinned Java | **49/49**, the same **16** divergences | 0 |
| `java-oracle` build against the pinned jar | — | 0 |
| `cargo fmt --all -- --check` | clean after formatting | 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean | 0 |
| `cargo test --workspace --all-targets --all-features` | all suites pass | 0 |
| `make -C rust gates` (with `VJWP_PROTECTED_STORE` exported) | `ac1-gates verdict=PASS gates_passed=8/8`; ledger integrity verified | 0 |
| `go test ./internal/divergencesweep/` | pass | 0 |

**The runtime neutralisation is disclosed and bounded.** The `--live` handshake
evaluator pins the recorded Java jar's identity, and the Rust harness honestly
reports its own; the port's transcript therefore has its `runtime` object — and
nothing else — rewritten to the accepted Java runtime before scoring. Measured:
**0 non-runtime fields moved, 0 remaining `ws-oracle-harness` mentions**. This
is the same bounded rewrite the repository's precedent uses
(`drafts/self-review/server-close-parity-round-1.md`).

**Port versus live Java, field by field** — identical to the recorded
precedent, so this branch shifted nothing:

- public tier, 74 shared cases: differs only in `/error/detail` (26 cases) and
  the two runtime fields (74 cases each).
- handshake tier, 49 shared cases: differs in **nothing but** the two runtime
  fields.

**Linkage refreeze.** `rust/ws-testee/src` and `rust/ws-core/src` changed, so
`evidence/linkage/*` went stale by construction. `go test ./internal/linkage/`
before: **exit 1** (`LINKAGE_VERIFICATION_DRIFTED`, `LINKAGE_DAG_DRIFTED`).
`LINKAGE_REGENERATE=1 go test ./internal/linkage/`: **exit 1**, by design while
regenerating. `go test ./internal/linkage/` after: **exit 0**. The diff is 61
insertions and 61 deletions across two files and contains **only** `sha256` and
`line` fields — no symbol lost a binding, no declaration text changed, no
verification flag flipped. All **163** file digests in the refrozen artifacts
were independently recomputed with SHA-256 over the real files: **0
mismatches**.

## 8. Findings on my own work

**Finding 1 — a divergence the sweep named could hide a second one inside it
(real).** DIV-06 named two missing fields and an unsorted order. Reading the
cited method showed a third difference in the same five lines: the `Connection`
value is echoed, not literal. It is invisible to every case the recorded run
contains. This is the strongest available argument for the task's instruction
not to take the sweep's word for it: the sweep's own account of DIV-06 says the
port "writes exactly three fields in a fixed order and neither of the two Java
adds", which is an accurate description of what it measured and an incomplete
description of the method it cites.

**Finding 2 — the fix's own doc comment was at risk of the same defect.** The
first draft of `accept_response`'s new comment said "five fields". That is a
count, and a count is what the old comment's "three" was. It now names each
field with its Java line number, states which two conditional fields are absent
and why they are absent, and cites the TreeMap separately for the ordering — so
a reader can check the citation against the method rather than against a
number.

**Finding 3 — a clockless core makes a forgotten clock silent.** Putting the
instant behind an injected value keeps `ws-core` pure, but it means a missing
adapter-side clock read produces a perfectly well-formed head that says 1970
forever, and every `ws-core` test still passes. Two things stop it: the
constructor has no clockless overload, and the two `ws-testee` liveness tests
(A6, A7) observe the real socket. Without A7 in particular, reading the clock
once per fixture would have passed.

**Finding 4 — the RED reading is weaker than the attacks, and is labelled so.**
Because the fix changes `ServerHandshake::new`'s signature, the permanent tests
cannot be compiled against unfixed source. The RED reading was taken with a
transient probe and the probe was then removed. Section 2 says this explicitly
rather than letting the reader assume the permanent tests were the ones run
red; section 5 is the evidence that they can fail.

## 9. Residual gaps, stated rather than closed

- **The Gregorian/Julian cutover is a real, disclosed non-fidelity.**
  `java_server_time` is proleptic Gregorian. Java's `GregorianCalendar`
  switches to the JULIAN calendar strictly before `1582-10-15T00:00:00Z`
  (epoch `-12219292800`), where the two disagree by the historical 10-day gap.
  Measured on the pinned JDK: epoch `-12219292801` renders as
  `Thu, 04 Oct 1582 23:59:59 GMT`, where the port would say `14 Oct`. Byte
  identity is claimed **at and after the cutover only**. No server clock
  reaches that region and a Julian branch nothing exercises would be
  speculative code, so the gap is disclosed in the function's doc comment
  rather than closed. The function is total over every `i64` regardless — no
  input panics, which is itself tested.
- **The 247-case sweep was NOT re-run.** Re-running Autobahn is an owner gate.
  Whether a fresh run would now show 0/247 on
  `subject_handshake_header_names` for the server role is **unmeasured**. What
  is claimed is what the pinned Java source and jar do, what the port's source
  and tests now do, and that the differential and exam are unmoved.
- **The Java claims are source citations plus an offline computation over the
  pinned jar — never a live socket observation.** The offline computation is
  strong evidence because it runs the real library code and reproduces the one
  recorded run's accept value, but it drives the library directly rather than
  through a server socket, so anything `WebSocketImpl` or the server I/O path
  might do to the head between `createHandshake` and the wire is out of its
  reach. The recorded run's `httpResponse` bytes are the check on that, and
  they agree.
- **`Sec-WebSocket-Extensions` and `Sec-WebSocket-Protocol` are untested
  because they are unreachable.** Java writes them only under a non-default
  extension or protocol, which this port does not configure. The port would
  need new configuration surface to emit them; nothing here claims fidelity for
  that configuration.
- **The `Connection` echo is now faithful to `getFieldValue`, which the port's
  header map already matched.** `JavaHeaders::get` implements Java's
  leading-space stripping and `"; "` duplicate joining, and that equivalence
  was relied on rather than re-established here; it is covered by
  `rust/ws-core/src/handshake/http.rs`'s own tests and the 49/49 handshake
  exam.
- **`TestDIV06IsClosedInThePortSourceItNames` reads source text, not
  behaviour.** It can be satisfied by source that contains the right literals
  in the right order without producing the right bytes. It is a cheap guard
  against a regression landing unnoticed in the Go plane; the behavioural proof
  is in the two Rust test files, and this document does not claim the Go check
  substitutes for them.
