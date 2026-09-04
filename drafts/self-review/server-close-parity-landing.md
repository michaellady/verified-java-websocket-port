# Landing record — claude/server-close-parity → mainline (goal-loop, parallel-agent track B)

Recorded 2026-09-02 by the goal loop from tool output. The branch was produced
by a parallel agent and carries its own review round,
`drafts/self-review/server-close-parity-round-1.md` (five deletion attacks, two
findings kept rather than buried). This record is the landing check the loop
ran on top of it — not an independent review: OWNER_ATTESTED_NOT_INDEPENDENT.

## What landed

One commit, `e9d0d10`, merged with mainline `99a9c7b`. Automatic merge, no
conflicts: mainline's only commits since the branch forked are `01ee515` (the
F004 fix, which the branch had already forward-merged) and `99a9c7b`
(`.claude/GOAL-LOOP.md` only). The merged tree is byte-identical to the branch
tree over `rust/`, `corpora/`, `java-oracle/`, `java-semantic-oracle/`,
`autobahn-endpoint/` and `java-crosspeer/` — `git diff --stat` against the
branch over those paths is empty, and the whole-tree diff is `.claude/GOAL-LOOP.md`
alone.

The change: `ws-testee`'s I/O loop now closes the TCP connection when a SERVER
reaches the drained (`Idle`) path in `ReadyState::Closing`, and a client never
does. `role` is a required parameter of `drive_connection`, so no call site can
acquire the behaviour — in either direction — by omission.

## The Java citation, re-read at source rather than accepted

I read the pinned tree myself rather than take the branch's word for it.
`.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667`:

- `src/main/java/org/java_websocket/SocketChannelIOHelper.java:110-113` is
  verbatim as cited: the `outQueue.isEmpty() && isFlushAndClose() && getDraft()
  != null && getRole() != null && getRole() == Role.SERVER` conjunction guarding
  `ws.closeConnection()`.
- `batch(` has **exactly one** caller in the whole source tree,
  `server/WebSocketServer.java:586`. The "server write path only" claim is not
  an inference; it is the complete call graph.
- `WebSocketImpl.closeConnection()` at `:573-578` delegates to
  `closeConnection(code, message, remote)`, which cancels the key and calls
  `channel.close()` at `:545-546`.
- The client counterpart genuinely does not exist:
  `client/WebSocketClient.java` `runWriteData` (`:837-851`) writes until the
  thread is interrupted, drains `outQueue`, and re-interrupts. It contains no
  `closeConnection` and no `isFlushAndClose` — the four `closeConnection` call
  sites in that file are all error paths (`:366`, `:512`, `:520`, `:552`).

The citation holds in full.

## Independent corroboration that arrived the same hour

The parallel divergence sweep (track C, `claude/divergence-sweep`) measured the
same gap from the other end, without either agent seeing the other's work: on
the pinned Autobahn native run, the port's SERVER left the socket to the peer on
**123 cases Java closed** (91 of them where the suite records "It is preferred
that the server close the TCP connection", 32 drop-timeout), and exactly one
case in 494 goes the other way. That sweep files it as DIV-02 and calls it the
second-largest close-behaviour class in the run. Two tracks, one source-derived
and one measurement-derived, agreeing on the same defect is the strongest
evidence this landing has.

## Two decisions the branch correctly refused to make alone

**1. The linkage refreeze: APPROVED, no overrule.** Editing the adapter makes
the linkage artifacts stale by construction — they record each mapped symbol's
declaring-file sha256. The agent refroze through the sanctioned
`LINKAGE_REGENERATE=1` path and flagged it for overrule. I read the diff: six
digest lines and one line number (`drive_connection` 159 → 164, which is exactly
the five lines its new doc comment added). No content, no edge, no node, no
rationale changed. That is a derived-index recomputation, not evidence
re-baselining, and `go test ./internal/linkage/` reads ok (exit 0) at the merged
head.

**2. The ledger framing: the branch's wider subject is ACCEPTED, and the append
is DEFERRED for a reason neither framing anticipated.**

The agent's argument was right as far as it went. For an *echoed* close the RFC
and Java agree, so recording that half alone would be a hollow record — its
only Autobahn support is an unobserved marker. Its proposed wider subject, the
role-gated transport close, names a real disagreement: Java gates on
`isFlushAndClose()` rather than on having *received* a Close, so a Java server
that INITIATES a close hangs up as soon as its own frame drains, earlier than
RFC 6455 §5.5.1 allows. The branch pins that sub-case with a test so the claim
is not unbacked. I accept that subject.

What neither framing saw is that **the live ledger cannot currently express what
this record needs to say.** `schemas/behavior-delta-ledger-1.1.0.schema.json`
defines `disposition` as `enum: ["unresolved", "rfc-governs"]`, and **all 48
records read `unresolved`.** US-020 AC3 requires every mismatch be appended "as
Java quirk, Rust defect, or underspecified behavior" — three classes, none of
which this vocabulary contains. Meanwhile the inherited foundation schema,
`assurance/schema/behavior-delta-ledger.schema.json`, defines exactly the axis
this record turns on — `classification: [PRESERVE, INTENTIONALLY_CORRECT,
UNRESOLVED]` — and the live ledger does not use it.

So the branch's observation that "this one is partly a divergence the port
*adopts*" is sharper than it appears: adoption versus preservation versus
correction is precisely the distinction the live ledger has no field for.
Appending this record as `disposition: unresolved` would file a deliberately
adopted, fully reasoned behaviour in the same bucket as 48 open questions —
existence standing in for identity, one level up from where this program keeps
meeting it.

Therefore: `drafts/ledger-proposals/server-close-parity.json` stays a DRAFT and
the ledger is untouched by this landing. The correct unit is to settle the
disposition vocabulary against US-020 AC3 first, then append this record and the
divergence sweep's six under it in one deliberated batch. Queued as such. The
ledger is append-only with a frozen prefix through sequence 35; a considered
batch beats seven scattered appends, and a wrong disposition cannot be taken
back.

## Residual, carried forward rather than closed

The branch's own round-1 findings, both kept:

- **The unit truth table survives deletion of the entire fix.**
  `only_a_closing_server_closes_the_transport_itself` exercises the predicate,
  and the predicate still exists when the call site is deleted. The three
  loopback integration tests are the only evidence the gate is WIRED (attack A1
  fails 3 server tests). Honest so long as nobody reads the truth table as
  coverage of the wiring — recorded here so nobody does.
- **`pending_chunk.is_empty()` has no failing witness.** Attack A5 removed that
  operand and the whole `ws-testee` suite stayed green (4 + 22 + 8 passed, exit
  0). It is a conservativeness guard — it stops the adapter hanging up while the
  driver still holds deferred inbound bytes — but no fixture in this suite
  reaches the gate with a deferred chunk, so nothing holds it in place. Kept,
  because removing it could drop deferred bytes; disclosed, because a line no
  check can fail is not evidence whatever its rationale.
  **A witness is constructible and is named for the track that can build it:**
  the pipelined-read carryover path on `claude/us019-native-run` (the Autobahn
  fuzzing server pipelines a frame behind its 101) is exactly the shape that
  reaches `Idle` with a non-empty `pending_chunk`. Build it when those trees
  meet.

Also named: no live Java socket observation exists on this plane. The
`java-oracle` is a JSONL request/response oracle and never opens a server
socket, so every Java claim in this branch is a source citation and is labelled
as one. The corroborating measurement above comes from the Autobahn suite's
observations, not from a Java socket this repository drives.

## Gates, read at the merged head

- `make -C rust gates` with the store exported: **exit 0**. fmt-check, clippy,
  test, test-release; `ac1-gates verdict=PASS gates_passed=8/8`;
  `adapter-linkage verdict=PASS` over 5 production sources; ledger integrity
  verified (48 records, frozen prefix through sequence 35, 3 supersessions,
  unledgered_disagreements recomputed = 0). 75 `test result: ok` blocks, **0
  failed**.
- `go build ./...` exit 0. `go test -count=1 ./internal/linkage/` exit 0 after
  the refreeze.
- The public differential and the handshake exam were NOT re-run at this head
  and cannot have moved: the merged tree is byte-identical to the branch over
  every behaviour-bearing path (proof above), and the branch measured port
  74/74 and 49/49 with the same 16 documented divergences, live Java 74/74 and
  49/49 with the same 16, handshake request digest `e00d968f…` equal to the
  batch-B receipt and harness digest `e2898c13…` unchanged.
- Environment note the branch surfaced and this loop confirms: `internal/benchplan`
  and `internal/formalplan` exceed Go's default 600s timeout under host
  contention (read 204.9s/257.7s uncontended, 496s/467s contended). Run the Go
  suite with `-timeout 40m`; a bare `go test ./...` reports a spurious FAIL that
  is host speed, not a defect.
