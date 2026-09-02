# Self-review round 1 — claude/server-close-parity

Recorded 2026-09-02T18:07:12Z from tool output on branch `claude/server-close-parity`,
branched from mainline `claude/feature/verified-java-websocket-port` at 8a7f713 and
forward-merged to mainline 01ee515 (the F004 owner-drop race fix) before landing.

The question asked of every check added on this branch: **if I deleted the code
this test describes, would this test fail?** Answered by execution — delete the
fix, run the suite, read the failure, restore. A check that cannot be made to
fail is not evidence.

## What the branch changes

`rust/ws-testee/src/io_loop.rs` gains `server_closes_transport(role, state)` —
`role == Role::Server && state == ReadyState::Closing` — consulted only on the
loop's drained (`Idle`) path. On the gate the adapter shuts the socket down and
hands the core `TransportEof`. `drive_connection` takes an explicit `role`
parameter; `server.rs` passes `Role::Server`, `client.rs` passes `Role::Client`.
`ws-core` and `ws-driver` are byte-unchanged (`git diff --stat` against mainline
over `rust/ws-core rust/ws-driver rust/ws-oracle-harness` is empty).

## The RED reading, taken before any source change

With the three server/client tests written and `rust/ws-testee/src` untouched,
`cargo test -p ws-testee --test loopback` exited **101**, `19 passed; 2 failed`:

```
thread 'a_server_closes_the_tcp_connection_once_its_close_echo_has_drained'
panicked at ws-testee/tests/loopback.rs:1200:5:
shipped Java's server closes the TCP connection once the echo has drained
(SocketChannelIOHelper.java:110-113 -> WebSocketImpl.java:546); the peer saw the
echo and then no EOF, so this endpoint left the socket open

thread 'the_server_fixture_reaches_its_terminal_without_the_peer_ever_closing'
panicked at ws-testee/tests/loopback.rs:1311:5:
and the server closes the connection behind it
```

Two readings worth keeping from that run:

- In the first test the **echo assertion passed** and only the EOF assertion
  failed. The divergence was precisely "no TCP close", not a missing or
  malformed close echo.
- `a_client_does_not_close_the_tcp_connection_after_its_close_echo` passed
  RED-side, as it must: the client half already matched Java. It is a
  regression guard against over-applying the fix, not a reproduction — and
  attack A2 below is what proves it has teeth.

## Attack matrix

Each attack mutates `rust/ws-testee/src/io_loop.rs` only, runs the `ws-testee`
lib and loopback targets, and is then restored. Restored file sha256
`6cdc350fe87b1faea5927c7baf39f4c713c3eda3663c71c137a75d1e0719f2bc`, matching the
digest recorded in `evidence/linkage/`.

### A1 — delete the whole gate block

Removed the `if server_closes_transport(...) { ... }` branch entirely.

- loopback: **FAILED, 19 passed / 3 failed** —
  `a_server_closes_the_tcp_connection_once_its_close_echo_has_drained`,
  `the_server_fixture_reaches_its_terminal_without_the_peer_ever_closing`,
  `a_server_that_initiates_a_close_hangs_up_without_waiting_for_the_echo`.
- lib: **ok, 4 passed** — including
  `only_a_closing_server_closes_the_transport_itself`.

**This is the finding of the round.** The unit test survives deletion of the
entire fix, because it exercises the predicate and the predicate still exists;
nothing in it reaches the loop that consults it. The unit test is a truth table
for the role gate and nothing more — the three integration tests are the only
evidence that the gate is *wired*. Recorded rather than removed: the truth table
is what A2 and A3 fail on fastest, and it is honest so long as nobody reads it
as coverage of the wiring.

### A2 — drop the role half

`server_closes_transport` rewritten to `state == ReadyState::Closing`, ignoring
the role, so both endpoints hang up.

- lib: **FAILED, 3 passed / 1 failed** —
  `only_a_closing_server_closes_the_transport_itself` at `io_loop.rs:686`.
- loopback: **FAILED, 20 passed / 2 failed** —
  `a_client_does_not_close_the_tcp_connection_after_its_close_echo`, panicking
  with exactly its intended message ("shipped Java's CLIENT has no such branch
  (WebSocketClient.java:837-851)…"), and `one_byte_write_chunks_still_complete_the_round_trip`.

The client guard has teeth, and an unconditionally-closing client also breaks a
shipped round trip that predates this branch. The role half is load-bearing in
two independent places.

### A3 — drop the state half

`server_closes_transport` rewritten to `role == Role::Server`, ignoring the
state, so a server hangs up while still `Open`.

- lib: **FAILED, 3 passed / 1 failed**.
- loopback: **FAILED, 12 passed / 10 failed** — including
  `echo_round_trip_with_clean_close`, `autobahn_7_3_2_wire_reply_is_1002_end_to_end`,
  `a_protocol_failure_after_a_committed_close_echo_still_delivers_the_echo`,
  `sequential_sessions_reuse_the_listener`, and the new server tests.

`ReadyState::Closing` — this side's image of Java's `isFlushAndClose()` — is
heavily load-bearing; a server that closes while Open destroys the suite.

### A4 — close the socket but never tell the core

Kept `stream.shutdown(Both)`, deleted the `pump(driver, DriverInput::TransportEof, …)`
that follows it.

- lib: **ok, 4 passed** (the predicate is untouched).
- loopback: **FAILED, 13 passed / 9 failed** — including both new server tests,
  each failing on its `report.clean()` assertion with the summary read directly:

```
closing the transport is what carries this run to its terminal:
outcome=BudgetExhausted texts=0 binaries=0 pings=0 pongs=0 close=1000:transport terminals=0

the peer never closed its side, so only a server-side close can carry this run
to its exactly-once terminal:
outcome=BudgetExhausted texts=0 binaries=0 pings=0 pongs=0 close=1000:transport terminals=0
```

This is the attack the EOF assertion alone would have survived: the peer *does*
see EOF under A4, and only the `clean()` assertion notices that the run never
reached its exactly-once terminal. Both assertions are needed; neither is
redundant.

### A5 — remove the `pending_chunk.is_empty()` operand

Gate condition reduced to `server_closes_transport(role, driver.state()) && !eof_seen`.

- **Whole `ws-testee` suite ok, exit 0**: `4 passed` (lib), `22 passed`
  (loopback), `8 passed` (process). Nothing turned red.

So that operand is an **unproven line**, and this is measured rather than
argued. It is a conservativeness guard — it stops the adapter hanging up while
the driver still has deferred inbound bytes — but no test in this suite reaches
the gate with a deferred chunk, so nothing holds it in place. Kept because
removing it could drop inbound bytes the driver deferred; disclosed here because
a line no check can fail is not evidence, whatever its rationale.

## Restored

`cargo test -p ws-testee` after restore: `4 passed` (lib), `22 passed`
(loopback), `8 passed` (process), exit **0**. Restored `io_loop.rs` sha256
`6cdc350fe87b1faea5927c7baf39f4c713c3eda3663c71c137a75d1e0719f2bc`.

## Limits of this round, stated plainly

- **No live Java socket observation.** Java's behaviour here is established by
  reading the pinned source (`SocketChannelIOHelper.java:110-113` and the chain
  around it), not by executing a Java server and watching the FIN. The
  `java-oracle` adapter is a JSONL request/response oracle and never opens a
  server socket, so nothing on this plane observes which endpoint closes TCP.
  Every claim about Java in the code comments, the ledger draft and this record
  is a source citation, and is labelled as one.
- **No Autobahn run.** Not executed here by instruction; the ledger draft's
  `autobahn_refs` carry the honest non-execution markers.
- **The unit test does not cover the wiring** (A1). Stated above rather than
  papered over.
- **`pending_chunk.is_empty()` in the gate condition has no failing witness**,
  confirmed by execution in attack A5 rather than assumed: the whole suite
  stays green without it, exit 0.

## Validation on the merged tree, exit codes read from the process

- `make -C rust gates` — **exit 0**, `ac1-gates verdict=PASS gates_passed=8/8`,
  `gate=adapter-linkage verdict=PASS` (the adapter still names no forbidden
  protocol symbol), `ledger-gates` ok. `rust/ws-testee` loopback reads
  `22 passed` in both the debug and release legs. The F004 race test passes on
  both legs with mainline's wall-clock bound in.
- `go build ./...` — **exit 0**.
- `go test -count=1 ./...` — exit 1, with the two documented Linux-environment
  failures and nothing else attributable to this branch:
  - `internal/lab` — `PLATFORM_EXECUTOR_UNSUPPORTED`, requires Darwin `sandbox-exec`.
  - `internal/portplan` — `ORACLE_REPRODUCTION_MISMATCH`, vendor-bound to a
    Homebrew OpenJDK host.
  - `internal/benchplan` and `internal/formalplan` additionally hit Go's default
    600s per-package timeout on a contended pass (they had read 204.9s/187.4s
    and 257.7s/245.0s on two earlier passes of this same tree). Re-run in
    isolation with `-timeout 30m` both read **ok**, 600.180s and 595.349s,
    **exit 0**. Host speed, not a defect, and disclosed rather than hidden.
  - `internal/linkage` failed once and that failure WAS this branch's: the
    artifacts record, per mapped symbol, the declaring file's sha256, and
    editing `io_loop.rs`/`client.rs`/`server.rs` makes those stale by
    construction. Refrozen through the sanctioned path
    (`LINKAGE_REGENERATE=1 go test -run TestRegenerateLinkageArtifacts ./internal/linkage/`,
    exit 0), which is the repository's established workflow for a Rust source
    change (precedent: commits d25a9f3, 04f6c8e, b01a4f4). The regeneration
    diff is **only** the three files' digests plus `drive_connection`'s line
    moving 159 -> 164; every new digest was checked against `sha256sum` of the
    real file. No symbol lost a binding, no declaration text changed, no
    verification flag flipped. `go test ./internal/linkage/` then exit 0.
- Corpus differential and handshake exam, re-run on the merged tree.
  `ws-core`, `ws-driver` and `ws-oracle-harness` are byte-identical to mainline
  (`git diff --stat FETCH_HEAD` over the three is empty) and the release harness
  digest is unchanged at
  `e2898c138cdbe291c1f20938ddfa370f05632c138ce4b87d8feb718dfb870873`, so the
  corpus path cannot have moved — and it did not:
  - handshake request digest
    `sha256:e00d968f0ae623dd75a09842ad435642c0dca53ee5e9f9ef654ce26c1f814c49`,
    equal to the batch-B receipt. **No corpus shift.**
  - port: public **74/74**, handshake exam **49/49** with the 16 documented
    divergences (runtime field neutralized to the accepted Java runtime and
    nothing else — 0 remaining harness mentions, 0 non-runtime fields moved).
  - live pinned Java (JDK 17.0.19+10, `-Dsun.stdout.encoding=UTF-8`): public
    **74/74**, handshake **49/49**, the same 16 divergences; `java-oracle`
    self-test PASS 18.
  - port versus live Java, field by field: public tier differs only in
    `/error/detail` (26 cases) and the runtime fields; handshake tier differs
    in nothing but the runtime fields. Identical to the reading recorded in
    `.claude/CLOUD-ENVIRONMENT.md`.
  - The public and handshake tiers were regenerated from the committed public
    seed with a throwaway protected-root secret, which those two tiers do not
    consume. No hidden or sealed tier was generated or scored, and this is not
    a custodian-ledgered run.
- No Autobahn, AWS or benchmark run was triggered. `evidence/java/behavior-delta-ledger.json`
  is untouched — still 48 records, head
  `sha256:ab9277cb6bf4c822196999367a91bb6f357296b7b2584c3489cbe893cf78c2ac`,
  frozen prefix intact. The proposed record is drafted at
  `drafts/ledger-proposals/server-close-parity.json` and **must be appended at
  landing time**, which is a Go `Definition` addition plus a regeneration, not a
  JSON edit.
