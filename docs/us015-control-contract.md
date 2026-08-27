# US-015 bounded ping/pong control contract

Status: execution-ready architecture at
`dca0fdb7face1c391d6f4b36ca58642aec76a49b`

Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`

Claim ceiling: `BOUNDED_TEST_EVIDENCE`

## Scope

US-015 deepens the existing dependency-free
`websocket_core::ConnectionCore` module at its only mutable seam:

```rust
ConnectionCore::step(CoreInput::Transport(_)) -> StepResult
ConnectionCore::step(CoreInput::Command(_)) -> StepResult
```

It makes valid Ping and Pong control frames semantically observable, supports
an optional same-step automatic Pong for the server role, and makes local
Ping/Pong commands emit one canonical control frame. All behavior runs through
the real `ConnectionCore::step` path and reuses the existing `FrameDecoder`,
immutable `Frame` payload owner, and explicit-key `FrameEncoder`.

Ping and Pong remain final, have RSV bits clear, and carry at most 125 payload
bytes. The existing US-012 header decoder continues to enforce those wire
rules and role masking before US-015 control semantics run. Valid controls may
occur before, between, or after data fragments and never read, append, reset,
finish, or otherwise mutate the US-014 fragment accumulator or UTF-8
validator.

US-015 does not add wall-clock timers, keepalive scheduling, lost-connection
policy, sockets, callbacks, compression, extensions, close-code construction,
close writes, or EOF behavior. The `Closing` lifecycle is not reachable until
US-016 and its inbound/outbound control rules remain owned there. This story
implements control behavior only while `ConnectionState::Open`.

No Autobahn rerun, live Java execution, external fuzz or mutation engine,
formal backend, signing, publication, production, or independent-review claim
is authorized. Existing recovered observations remain under their original
provenance and do not become new US-015 execution evidence.

## Architectural decision: one private control module

`ConnectionCore` remains the only public protocol module. The existing private
`control` module becomes one small deep implementation that owns:

- Ping/Pong semantic classification and immutable payload sharing;
- automatic-response policy and role legality;
- event, write-entry, encoded-byte, and checked-arithmetic admission;
- deterministic planning of inbound output groups;
- local-command validation and delegation to `FrameEncoder`;
- failure precedence and whether a failure is terminal or nonterminal.

The control module does not parse wire bytes, apply an inbound mask, accumulate
fragments, own a clock, source entropy, or maintain a second output queue.
`FrameDecoder` remains the sole wire decoder. `FrameEncoder` remains the sole
implementation of canonical outbound framing and masking.

The private coordination interface should remain no larger than a batch
preflight plus an encoder operation; exact private names may change during
TDD:

1. inspect decoded records in wire order and return the accepted prefix,
   required output capacity, required automatic-write count and bytes, and an
   optional failure before public-output or wire allocation;
2. encode an already-admitted automatic or local control frame with the
   existing `FrameEncoder`;
3. create `Ping`/`Pong` semantic values by cloning only the decoded frame's
   `Arc<Vec<u8>>` owner.

The interface is the test surface: public tests use `ConnectionCore::step`, not
a public control parser or planner. Deleting the module would spread policy,
role checks, queue accounting, aggregate write-byte accounting, ordering, and
mask-key rules across the frame decoder and connection dispatch. Its depth
therefore creates locality without inventing an adapter seam.

## Public policy, commands, and semantic values

Automatic Pong is explicit checked configuration, defaulting to disabled so
existing `ConnectionConfig::try_from(ConnectionLimits)` behavior remains
source-compatible:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomaticPongPolicy {
    Disabled,
    ServerOnly,
}

impl ConnectionConfig {
    pub const fn with_automatic_pong_policy(
        self,
        policy: AutomaticPongPolicy,
    ) -> Self;

    pub const fn automatic_pong_policy(&self) -> AutomaticPongPolicy;
}
```

`ServerOnly` means exactly that an open server core automatically emits an
unmasked Pong for each accepted inbound Ping. It has no effect on a client
core. There is deliberately no misleading `Enabled` value that silently
promises an unsafe client response.

The two existing placeholder commands gain one explicit per-frame key field:

```rust
pub enum LocalCommand {
    // existing variants
    SendPing {
        payload: Box<[u8]>,
        mask_key: Option<[u8; 4]>,
    },
    SendPong {
        payload: Box<[u8]>,
        mask_key: Option<[u8; 4]>,
    },
}
```

For `Role::Client`, `mask_key` is required and is consumed for exactly that
one frame. For `Role::Server`, `mask_key` is forbidden. These rules reuse the
existing `FrameFailure::MissingMaskKey` and
`FrameFailure::UnexpectedMaskKey` values from `FrameEncoder`.

The core never generates, derives, stores, caches, repeats, or retries a client
mask key. The caller is responsible for supplying an independently generated,
unpredictable fresh key for every client frame. Supplying the same four bytes
in two separate commands violates the caller-side freshness contract; the
Sans-I/O core cannot prove entropy quality or global uniqueness without either
unbounded history or an entropy adapter. The implementation must not imply
that accepting an explicit key certifies randomness.

Inbound semantic observations share the existing immutable frame backing:

```rust
pub struct ControlPayload { /* private Arc<Vec<u8>> owner */ }

impl ControlPayload {
    pub fn as_slice(&self) -> &[u8];
}

pub enum SemanticEvent {
    // existing events
    Ping { payload: ControlPayload },
    Pong { payload: ControlPayload },
}
```

`ControlPayload` has no public constructor or mutation path. Constructing it
from `Frame::payload_owner()` clones one Arc, not the payload bytes. It is a
semantic value rather than a second frame: callers do not have to inspect an
opcode to know which event occurred.

## Owner-relaxed client automatic-Pong decision

RFC 6455 requires every client-to-server frame to use a fresh unpredictable
masking key. `CoreInput::Transport` supplies peer bytes only; it does not carry
local entropy. Therefore an inbound client Ping cannot safely cause a masked
Pong in the same step unless a fresh key was supplied before that step.

US-015 does not add a mask-key queue, reserve keys for future peer behavior, or
invent a fixed, derived, zero, counter, payload-based, handshake-based, or
previously used key. Under both automatic policies, an open client emits only
the inbound frame and Ping event. Its caller may immediately issue
`SendPong { payload, mask_key: Some(fresh_key) }` in a later step.

This is the explicit owner-relaxed compatibility delta: automatic Pong is
fully implemented for servers and safely observable-but-manual for clients.
Future runtime work may pair the Sans-I/O core with an entropy source, but it
must do so through a newly designed explicit seam rather than weakening this
contract.

## Exact inbound behavior and output order

For one accepted Ping or Pong record, output order is indivisible and stable:

```text
client role, Ping, either policy:
    SemanticEvent::FrameReceived(frame)
    SemanticEvent::Ping(payload)

server role, Ping, Disabled:
    SemanticEvent::FrameReceived(frame)
    SemanticEvent::Ping(payload)

server role, Ping, ServerOnly:
    SemanticEvent::FrameReceived(frame)
    SemanticEvent::Ping(payload)
    TransportWrite(Pong with byte-identical payload)

either role, Pong, either policy:
    SemanticEvent::FrameReceived(frame)
    SemanticEvent::Pong(payload)
```

The automatic Pong is final, has RSV bits clear, has opcode Pong, is unmasked
because only the server emits it, and contains the exact unmasked inbound Ping
payload. It produces no extra local `Pong` semantic event. A received Pong
never produces a write. A local SendPing/SendPong produces exactly one
`TransportWrite` and no inbound semantic event.

Several decoded records in one transport input repeat their complete groups in
wire order. For example, a server receiving Ping(`a`), Pong(`b`), Ping(`c`)
under `ServerOnly` emits:

```text
Frame(Ping a), Ping(a), Write(Pong a),
Frame(Pong b), Pong(b),
Frame(Ping c), Ping(c), Write(Pong c)
```

Data frame/message groups keep their established US-013/US-014 order. A
control group appears exactly at its wire position. There is no deferred
write reordering at the end of the batch.

## Fragmentation preservation

US-014 already classifies valid Ping/Pong headers as control frames while a
fragment is active. US-015 layers semantic observation and optional response
only after that frame has decoded successfully. The control module receives an
immutable frame and has no reference to `FragmentAccumulator` or
`Utf8Validator`.

Before and after every accepted interleaved control frame, all of the following
are identical:

- active fragmented kind (`None`, Text, or Binary);
- accumulated message length and bytes;
- Text validator absolute offset and pending scalar state;
- next required continuation transition.

This holds for zero-byte and 125-byte controls, multiple consecutive controls,
arbitrary transport splitting, and controls coalesced with the final
Continuation. The final data message and its event order must be byte-for-byte
identical to the same sequence with the controls removed.

Close remains a frame-only US-016 record in this story and is not misclassified
as Ping or Pong. No automatic control response is emitted for Close.

## Payload and role legality

The existing frame codec owns all wire legality:

- inbound controls require FIN and clear RSV bits;
- an inbound server peer sends unmasked frames to a client core;
- an inbound client peer sends masked frames to a server core;
- an outbound client local command requires one explicit mask key;
- an outbound server local command forbids a mask key;
- payload length 0 and every value through 125 are legal;
- payload length 126 fails with
  `FrameFailure::ControlPayloadTooLarge { length: 126 }` before payload or
  output growth.

Control length is checked before the general FrameBytes cap and before mask-key
legality, matching `FrameEncoder` and `FrameHeaderDecoder`. A configuration may
set FrameBytes below 125; in that case the lower configured frame cap still
applies after the protocol's absolute 125-byte cap.

Inbound payload is unmasked exactly once by `FrameDecoder`. The Frame,
Ping/Pong semantic value, and automatic Pong encoder all observe those same
unmasked bytes. The automatic write never copies into a second temporary
payload buffer: `FrameEncoder` borrows the frame payload and copies it directly
into the one owned wire buffer required by `TransportWrite`.

## Pre-admission and checked retention

US-015 changes decoder semantic-event pre-admission. A valid Ping or Pong now
requires two event slots, not the one frame-only slot reserved by US-014:

1. `FrameReceived`;
2. `Ping` or `Pong`.

Close remains one event slot. Final data and fragmented-message slot counts
remain unchanged. The decoder must retain the control opcode in its fragment
plan (for example `FragmentPlan::Control(Opcode)`) so it can admit two slots
for Ping/Pong and one for Close before frame payload reservation. Exact event
capacity succeeds. Boundary plus one returns
`FailureKind::Backpressure(QueueKind::Event)` before payload growth and emits
no event for the offending control.

Automatic write admission happens in a pure first pass over decoded records,
before `CoreOutput` capacity or encoded-wire allocation. The pass identifies
the maximal accepted prefix and checks, with checked arithmetic:

- one `WriteQueueEntries` slot for each server automatic Pong;
- the exact encoded Pong length (`2 + payload_length`, because server control
  frames are unmasked and payload length is at most 125);
- aggregate retained payload and generated wire bytes against
  `TotalBufferedBytes` for all outputs simultaneously owned by the returned
  `StepResult`;
- the exact number of public outputs needed by the accepted prefix and a
  possible terminal `StateChanged(Closed)`.

The inbound decoder already accounts for distinct frame and fragmented-message
payload backings. The control preflight adds every generated wire buffer to
that retained total. The Ping/Pong semantic Arc is not counted again because
it shares the frame payload. Vector and Arc control-block capacity is not
payload bytes, but every actual inbound payload backing and outbound wire byte
is counted exactly once.

If a later coalesced Ping exceeds write entries or aggregate bytes, the
preflight stops before that record. The second pass reserves the admitted
output capacity once and emits only earlier groups. For each accepted automatic
Ping it encodes the Pong before publishing that Ping's Frame/Ping events, so an
encoder allocation failure cannot expose an offending semantic group. The
failure then appends one `StateChanged(Closed)` after all earlier groups.
Write-entry refusal is `FailureKind::Backpressure(QueueKind::Write)`;
aggregate generated-byte refusal is `FailureKind::LimitExceeded` for
`LimitKind::TotalBufferedBytes`. Neither condition is mislabeled as a peer
frame-syntax failure.

`ConnectionConfig` adds only crate-private checked accessors for
`write_queue_entries` and any total-retention value needed by this preflight.
No adapter-local cap or unbounded queue is introduced. The plan must use the
encoder's canonical wire-length logic or a crate-private checked encoder
preflight; it must not create a divergent second length encoder.

For a local SendPing/SendPong, admission is simpler and still precedes
allocation:

1. require `Open`;
2. validate the 125-byte protocol cap, configured FrameBytes, and role/key
   combination through the existing encoder rules;
3. admit one write entry and the exact encoded wire length against
   TotalBufferedBytes;
4. allocate/encode one wire buffer;
5. return one `TransportWrite`.

The nonzero checked configuration makes one write slot normally available,
but the implementation must use the same admission path rather than assuming
that fact. Command-channel admission remains owned by the existing bounded
command channel; `step(Command(...))` does not enqueue a second command.

## Failure precedence and state effects

Inbound failure precedence is deterministic:

1. existing reserved-bit, opcode, FIN, canonical-length, control-125, role-mask,
   platform, FrameBytes, and inbound TotalBufferedBytes checks;
2. existing fragmentation-transition checks without mutating active data;
3. two semantic event slots for Ping/Pong;
4. frame payload reservation, copy, and unmask;
5. automatic write-entry and aggregate generated-byte preflight;
6. output reservation and automatic wire allocation.

An inbound peer-syntax failure, event/write backpressure, checked arithmetic
failure, aggregate-byte refusal, output allocation failure, or automatic Pong
allocation failure is terminal under the current owner-relaxed core. It
preserves every earlier complete output group in order, emits no Frame,
Ping/Pong event, or write for the offending control, then emits one
`StateChanged(Closed)`. `FrameDecoder::reset` clears any partial frame and
fragment state. No Close wire is fabricated before US-016.

A local command failure is nonterminal because no peer bytes were consumed.
Invalid payload length, configured caps, role/key mismatch, backpressure,
checked arithmetic, or allocation failure returns no output and leaves the
open core and all active inbound fragmentation state unchanged. Local commands
cannot observe or mutate the inbound fragment accumulator.

In `Connecting`, local SendPing/SendPong returns
`InvalidState { input: LocalCommand, state: Connecting }` with no effect.
`Closed` retains the existing invalid-state behavior. `Closing` is not entered
or implemented by US-015: once US-016 makes it reachable, that story must
decide whether received or local Ping/Pong is accepted, ignored, or rejected.
US-015 tests must not manufacture a private Closing state and claim behavior
that the public core cannot reach.

## TDD matrix through the shipped seam

Tests exercise `ConnectionCore::step` and the public values returned from it.
They do not expose the private planner for convenience.

### Inbound behavior

- Ping and Pong payload lengths 0, 1, 124, and 125 for both endpoint roles;
- payload 126, fragmented controls, RSV1/2/3, reserved opcode, and wrong MASK
  bit, proving no offending event or write;
- all Ping payload bytes, including NUL and invalid UTF-8, preserved exactly;
- Disabled and ServerOnly policy for client and server cores;
- Pong never replies; automatic server Pong has FIN, Pong opcode, no mask, and
  byte-identical payload;
- every wire split through header, mask key, and payload, plus one-byte feeds
  and empty transport inputs;
- Ping/Pong before, between, and after fragmented Text/Binary, including a
  Unicode scalar split across fragments;
- multiple coalesced Ping/Pong controls and mixtures with unfragmented and
  fragmented data, asserting the complete ordered output list;
- a valid prefix followed by every malformed, over-event, over-write,
  over-total, arithmetic, or injected allocation failure.

### Local commands

- client SendPing/SendPong with an explicit key produces a correctly masked
  frame whose decoded payload is identical;
- missing client key and unexpected server key return the existing exact frame
  failures with no state change;
- server SendPing/SendPong produces one unmasked frame;
- payload 0 and 125 succeed; payload 126 fails before wire allocation;
- configured FrameBytes and TotalBufferedBytes exact/+1 boundaries;
- one write entry admitted before encoding and injected allocation refusal;
- Connecting and Closed rejection, with Closing explicitly absent/deferred;
- repeated commands prove the core does not cache or reuse a prior key; each
  emitted client frame contains exactly the key supplied by that command.

### Queue and retention boundaries

- EventQueueEntries exact two for one Ping/Pong and boundary minus one;
- several coalesced controls at exact event capacity and the first +1 record;
- WriteQueueEntries exact for N automatic server Pings and N+1, with the
  earlier N groups retained and no offending group;
- TotalBufferedBytes exact/+1 while simultaneously retaining decoded frames,
  fragmented-message backing, shared control semantic payloads, and generated
  Pong wire buffers;
- checked-add overflow models for event, write, output, and aggregate-byte
  arithmetic;
- refusal before prohibited output/write growth and unchanged active fragment
  state for every successful interleaved control.

## Seeded runtime and property coverage

`rust/connection-core/fuzz-seeds/us015/` contains small inert hex schedules,
not an external fuzz claim. The inventory covers empty Ping/Pong, 125 and 126
payloads, fragmented control, each wrong-mask direction, client/server policy,
control interleaving, multiple coalesced controls, event/write/total limits,
valid-prefix failure, and the retained payload-loss, wrong-opcode,
unwanted-reply, fragment-state-corruption, and limit regressions.

A deterministic replay test inventories every seed and feeds it through
`ConnectionCore::step` under recorded role, policy, command, and transport
chunk schedules. Fixed-domain property tests vary payload bytes and length,
role, policy, explicit client key, control opcode, fragment insertion point,
coalescing, and every transport split. The model predicts exact semantic
payloads, wire bytes, output order, failure, connection state, and final data
message.

Retained regression tests target the five named defect classes directly. They
are ordinary executable tests; without a genuinely run external mutation or
fuzz engine, the receipt must not say that mutants were killed or fuzzing ran.
The owner-relaxed completion claim is that the regression tests fail when the
corresponding defect is deliberately reintroduced in review, not that a new
mutation campaign occurred.

## Evidence handoff

`evidence/us015-control.json` is a compact receipt bound to the exact source
tree and records:

- assurance `OWNER_ATTESTED_NOT_INDEPENDENT` and
  `independent_review_claimed: false`;
- the architecture, implementation, test, seed-inventory, and evidence file
  digests;
- exact debug and release commands, exit status, and test totals;
- the policy/role/payload/chunk/interleaving/queue boundary matrix actually
  executed through `ConnectionCore::step`;
- source-derived or recovered external inputs only under their original
  provenance, clearly separated from current execution;
- unavailable/deferred rows for Autobahn category 2, live Java differential,
  external fuzz, external mutation, formal backend, signing, publication, and
  production.

No giant telemetry fixture is needed. The receipt summarizes counts and binds
small seeds by digest; the executable tests remain the replayable evidence.

## Implementation handoff

- `rust/connection-core/src/control.rs`: private policy/planner, role/key
  validation orchestration, queue and aggregate-wire preflight, shared
  `ControlPayload` construction, exact group ordering, and encoder delegation.
- `rust/connection-core/src/frame/decode.rs`: retain sole wire decoder; carry
  Ping/Pong opcode into control planning; pre-admit two event slots before
  payload reserve; keep Close at one; expose sufficient retained-payload
  accounting for control batch preflight without exposing parser state.
- `rust/connection-core/src/fragment.rs`: distinguish
  `Control(Ping|Pong|Close)` for slot admission while preserving active state;
  do not add response policy or writes here.
- `rust/connection-core/src/frame/encode.rs`: reuse canonical encoding; if
  needed, add one crate-private checked wire-length preflight shared by
  `encode`, never duplicate length logic.
- `rust/connection-core/src/connection.rs`: add `AutomaticPongPolicy`, checked
  config accessors, explicit-key SendPing/SendPong fields, `ControlPayload`,
  Ping/Pong events, Open-only command dispatch, inbound two-pass expansion,
  and terminal versus nonterminal failure effects.
- `rust/connection-core/src/lib.rs`: export only the stable policy and semantic
  payload values required by the existing public interface; keep planning
  private.
- `rust/connection-core/tests/ping_pong.rs`: real-seam policy, role, payload,
  ordering, masking, fragmentation-preservation, arbitrary-chunk, queue,
  retention, and failure tests.
- `rust/connection-core/fuzz-seeds/us015/`: inert replay schedules only.
- `evidence/us015-control.json`: compact source/test receipt with bounded
  owner-attested claims.

## Completion boundary

US-015 is complete when real debug and release gates pass and the shipped
`ConnectionCore` path emits byte-exact, deterministically ordered Ping/Pong
observations; emits configured server automatic Pongs and no unwanted reply;
encodes Open-state local commands with explicit role-correct keys; preserves
fragment state across arbitrary valid control interleaving; rejects malformed,
oversized, wrong-role, over-event, over-write, over-byte, and allocation cases
before prohibited output; and retains only valid prefix groups on terminal
inbound failure.

Completion makes no client automatic-Pong, entropy-quality, global key-
uniqueness, Closing, Close/EOF, wall-clock keepalive, Autobahn, live-Java,
external fuzz/mutation, formal, independent-review, signing, publication,
production, or release claim.
