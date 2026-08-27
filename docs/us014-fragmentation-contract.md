# US-014 bounded fragmentation contract

Status: execution-ready architecture at
`0be07662d009c993ca197149b7b2fbd4df2f471c`

Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`

Claim ceiling: `BOUNDED_TEST_EVIDENCE`

## Scope

US-014 deepens the existing dependency-free
`websocket_core::ConnectionCore` module at its only mutable seam:

```rust
ConnectionCore::step(CoreInput::Transport(_)) -> StepResult
```

It reassembles one inbound fragmented Text or Binary message at a time. A
non-final Text or Binary frame begins the message, zero or more non-final
Continuation frames extend it, and one final Continuation frame completes it.
Each accepted frame remains observable. The final continuation produces the
same public `TextMessage` or `BinaryMessage` value introduced by US-013.

Ping, Pong, and Close may occur between fragments. In this owner-relaxed slice
they remain validated, unmasked, frame-only observations and do not mutate the
active fragment kind, accumulated bytes, or UTF-8 validator. Ping/Pong events
and automatic writes remain US-015. Close payload semantics, lifecycle
transitions, close writes, and normal EOF remain US-016.

US-014 does not add outbound fragmentation or make `SendText` or `SendBinary`
available. It does not add compression, extensions, sockets, callbacks,
runtime ownership, ambient randomness, or a second frame parser.

No Autobahn rerun, live Java execution, external fuzz or mutation engine,
formal backend, signing, publication, production, or independent-review claim
is authorized. Existing recovered results may be referenced only with their
original provenance and may not be promoted into a new execution claim.

## Architectural decision: one private accumulator

`ConnectionCore` remains the only public protocol module. US-014 adds a
private `fragment` implementation and keeps the public interface unchanged
except for a stable fragmentation-failure value. `FrameDecoder` owns exactly
one `FragmentAccumulator` and calls it from the existing header/payload loop.
The accumulator never reads wire bytes, parses a header, applies a mask, or
emits public outputs.

This placement keeps the seam deep:

- `FrameDecoder` remains the sole implementation of wire framing, masking,
  chunk resumption, and per-frame payload retention;
- `FragmentAccumulator` owns only legal message transitions, message-global
  length, copied reassembly bytes, and message-global UTF-8 state;
- `ConnectionCore` expands accepted decoded records into public outputs and
  commits terminal state changes.

Deleting `FragmentAccumulator` would force transition, accumulated-length,
UTF-8-continuation, and reset logic back into the decoder loop. It therefore
creates locality and leverage without inventing an adapter seam. There is one
decoder and one accumulator, not two interchangeable adapters.

The accumulator's private coordination interface has four responsibilities;
exact internal names may be adjusted during TDD:

1. report persistent retained message bytes before the decoder validates a
   new header;
2. plan a complete validated header, rejecting an illegal transition and
   calculating message/event/total-byte admission before frame or accumulator
   allocation;
3. accept each newly unmasked payload range for message-global Text
   validation, then commit a complete accepted fragment to its reassembly
   buffer;
4. finish into an existing `TextMessage`/`BinaryMessage`, or reset on every
   terminal failure and EOF.

The existing fixed-state `Utf8Validator` is reused by the accumulator. A
separate instance may remain as frame-decoder scratch for US-013 unfragmented
Text; the validation implementation, failure vocabulary, and public message
values are not duplicated.

## Exact transition table

The active state is exactly `None`, `Text`, or `Binary`. The Text state also
contains one continuing `Utf8Validator`; both active states contain one
fallibly grown `Vec<u8>`.

| Active before | Inbound frame | Result |
| --- | --- | --- |
| None | `FIN Text` | unchanged US-013 Frame then Text delivery |
| None | `FIN Binary` | unchanged US-013 Frame then Binary delivery |
| None | non-final Text | begin Text, append payload, emit Frame |
| None | non-final Binary | begin Binary, append payload, emit Frame |
| None | any Continuation | `ContinuationWithoutMessage` failure |
| Text/Binary | non-final Continuation | append in order, emit Frame |
| Text/Binary | final Continuation | append, finish once, emit Frame then the active typed message, clear active state |
| Text/Binary | any Text or Binary | `DataFrameWhileFragmented` failure, regardless of FIN or data kind |
| any | final Ping/Pong/Close | emit Frame only; active state is byte-for-byte and validator-for-validator unchanged |

US-012 continues to reject a non-final control frame, a control payload above
125 bytes, reserved bits/opcodes, invalid masking, and noncanonical lengths
before fragmentation semantics run. A zero-length non-final Text/Binary frame
really begins a message. Empty non-final continuations are legal, and an empty
final continuation completes the active message. Completion is exactly once;
the next Continuation observes `None` and fails.

## Stable failures and precedence

US-014 adds one public stable category rather than overloading frame syntax or
UTF-8 failures:

```rust
pub enum FragmentFailure {
    ContinuationWithoutMessage,
    DataFrameWhileFragmented {
        active: Opcode,   // Text or Binary
        received: Opcode, // Text or Binary
    },
    UnexpectedEof {
        active: Opcode,   // Text or Binary
        accumulated: u64,
    },
}

pub enum FailureKind {
    // existing variants
    Fragment(FragmentFailure),
}
```

Exact field spelling may be mechanically adjusted, but the three distinct
categories and equality-stable data are contract. All three close the current
owner-relaxed core without writing a Close frame, produce one terminal
`StateChanged(Closed)`, and release all partial frame and message state.
US-016 may map the two sequence violations to close code 1002 when close-wire
construction exists; US-014 does not fabricate that write early.

Failure precedence is deterministic:

1. existing canonical header, opcode, control-frame, role-mask, platform, and
   FrameBytes checks;
2. existing accounting for the frame allocation under TotalBufferedBytes;
3. fragmentation transition legality;
4. checked whole-message, duplication-aware TotalBufferedBytes, and semantic
   event admission;
5. fallible frame/accumulator allocation and payload processing;
6. Text UTF-8 validation and finalization.

A final Text continuation ending within a scalar is
`Utf8Failure::TruncatedSequence`, because the peer declared the message
complete. EOF between frames while a fragmented message is active is
`FragmentFailure::UnexpectedEof`. EOF during an incomplete frame header or
payload remains `FrameFailure::UnexpectedEof`; the partial-frame condition
wins and all fragment state is still reset. EOF between frames with no active
fragment remains unavailable to US-016.

## Offending-frame observability

An offending fragment emits no `FrameReceived` event. This applies to an
orphan Continuation, a new Text/Binary frame during an active message, invalid
UTF-8 discovered in a fragment, truncation on the final continuation, a
message/total/event limit refusal, and allocation failure.

The decoder stages a record only after the frame's fragmentation transition,
payload append, and applicable UTF-8 work commit successfully. Emitting the
offending frame first would expose bytes as accepted and then reject the same
protocol action, and would diverge from US-013's rule for an invalid final Text
frame. Records completed before the offending frame remain observable in wire
order, followed by `StateChanged(Closed)`.

## Exact output ordering

Within one or many transport inputs, accepted outputs are normalized as:

```text
initial non-final Text/Binary       -> FrameReceived(frame)
non-final Continuation              -> FrameReceived(frame)
interleaved Ping/Pong/Close         -> FrameReceived(frame)
final Continuation                  -> FrameReceived(frame)
                                       Text(message) | Binary(message)
terminal failure after prior frames -> [all prior accepted outputs]
                                       StateChanged(Closed)
```

The message event is never emitted before its final continuation frame, never
emitted for an intermediate fragment, and never emitted twice. Several
complete fragmented and unfragmented messages in one input preserve wire
order. An interleaved control frame appears exactly where it occurred and has
no message event in US-014.

## Message-global strict UTF-8

For fragmented Text, the accumulator resets one `Utf8Validator` at the
initial Text header and feeds it only newly copied, already-unmasked payload
ranges in wire order. It does not finish the validator at an intermediate
frame boundary. A scalar may begin in any Text/Continuation fragment and end
in a later Continuation, under any transport split, including one-byte feeds
and empty transport chunks.

The validator's offset remains absolute from byte zero of the complete Text
message. Existing `Utf8Failure` categories and offsets are therefore stable
across fragment and transport boundaries. The validator finishes exactly once
after the final continuation payload. Binary fragmentation never feeds it.
Control frames neither feed nor reset it.

On the first invalid unmasked byte, the decoder stops processing that frame,
returns all earlier accepted records, clears the current frame and accumulator,
and reports `FailureKind::Utf8`. It does not append or expose the invalid
fragment.

## Checked retention and allocation

US-014 distinguishes the current frame payload from the persistent reassembled
message. The existing immutable `Frame` must retain its own `Arc<Vec<u8>>`, so
an accepted fragment's bytes are copied once into the accumulator while the
frame payload remains available for `FrameReceived`. The final accumulated
`Vec<u8>` is moved into one `Arc<Vec<u8>>` for the existing public Text/Binary
message value; finalization does not copy the whole message again.

For every complete header, define:

- `A`: bytes in the persistent accumulator before this frame;
- `S`: all distinct payload backing bytes retained by earlier accepted decoded
  records in the current `FrameDecodeBatch`: every Frame backing plus a
  separately finalized fragmented-message backing; an unfragmented
  frame/message pair shares one backing and is counted once;
- `P`: the new frame's declared payload length.

All conversions and additions below are checked. Before any frame payload
reservation, and before any accumulator capacity or length growth:

- every frame requires `P <= FrameBytes`;
- the existing decoder check requires `A + S + P <= TotalBufferedBytes`;
- a legal initial/continuation data fragment additionally requires
  `A + P <= MessageBytes`;
- because the fragment frame and accumulator coexist, it additionally requires
  `A + S + P + P <= TotalBufferedBytes` before appending;
- a control frame while fragmentation is active uses `A + S + P` and is never
  appended;
- an unfragmented final Text/Binary with no active message retains US-013's
  `S + P` accounting and does not create an accumulator copy.

`S` includes every distinct backing still owned by the current batch. `A` is
updated after each successful non-final append, so multiple fragments decoded
from one transport input account for both their accumulated copies and their
still-staged frame payloads. On final continuation, the accumulator backing is
moved rather than freed: `A` becomes zero and that full message length joins
`S` through the delivery record. This conservation is required before another
frame in the same batch is admitted. On a later `step`, prior results are no
longer retained by the core, so the decoder begins with the persistent `A`
only. Arc control blocks, record-vector capacity, and allocator spare capacity
are not payload bytes; all actual payload bytes owned by the core are included
exactly once per backing allocation.

Admission and mutation order for a legal fragment is:

1. validate the complete header and transition without mutating active state;
2. check `A + P`, `A + S + P + P`, and the required event slots;
3. fallibly reserve the frame payload and the accumulator extension;
4. install/start the planned state only after both reservations succeed;
5. copy and unmask each incoming range into the frame payload, feeding Text
   validation over that exact range;
6. at complete payload, append it to the accumulator, stage its frame record,
   and either retain active state or finalize the message owner.

If an implementation cannot atomically obtain both reservations, it may
reserve the accumulator immediately before append, provided every numeric cap
and event slot was already admitted at the header and failure still clears all
state without staging the offending frame. `try_reserve_exact` failure maps to
the existing `FrameFailure::AllocationFailed`.

## Event admission

Event capacity is checked from the current batch's staged semantic-event count
before any payload or accumulator allocation:

- initial fragment, non-final continuation, or control frame: one slot for
  `FrameReceived`;
- final continuation: two slots for `FrameReceived` and Text/Binary;
- illegal transition: no slot and no allocation;
- unfragmented final data: unchanged US-013 two-slot admission.

Exact capacity succeeds. Boundary plus one returns
`FailureKind::Backpressure(QueueKind::Event)`, preserves earlier records, emits
no offending frame, resets fragmentation, and closes once.

## Reset and release invariants

There is only one terminal reset path. `FrameDecoder::reset` clears its header,
current frame payload, frame scratch validator, and `FragmentAccumulator`.
`ConnectionCore::close_with_failure` continues to call that reset. Decoder
failures reset before returning their accepted prefix records.

The accumulator must be inactive with zero retained length and a reset
validator after:

- illegal transition;
- UTF-8 failure or final UTF-8 truncation;
- FrameBytes, MessageBytes, TotalBufferedBytes, or event refusal;
- checked arithmetic or platform conversion failure;
- allocation failure;
- malformed/partial frame terminal failure;
- EOF with an active message;
- successful final continuation after the message owner is moved out.

The Closed-state admission rule prevents reuse after a terminal failure, but
tests still assert release so a stale accumulator cannot leak into future
close/runtime work. Successful completion immediately permits a new fragmented
or unfragmented message in the same transport batch.

## Java observation and deliberate safety delta

The source-derived Java behavior has one active fragmented message, treats an
orphan Continuation or data-frame restart as protocol error 1002, and dispatches
control frames before fragmented-data handling so legal controls do not alter
the data sequence. Those observations inform the transition table only; no
live Java execution is claimed.

The observed Java cleanup path can leave its continuous-frame marker and
fragment buffer stale after a terminal failure. Rust deliberately does not
preserve that defect. Clearing the accumulator, validator, and current frame on
every terminal path is a story/RFC safety improvement and is recorded as an
intentional compatibility delta, not claimed as Java parity. The existing
neutral corpus cases for legal fragmented Text/Binary, Ping interleaving,
orphan Continuation, and data-during-fragment restart are replayed against the
shipped Rust seam with source-derived Java provenance kept distinct.

## TDD matrix through the shipped seam

Tests exercise `ConnectionCore::step`; they do not expose a parser or public
accumulator solely for testing.

### Legal sequences

- Text and Binary with one, two, and many Continuations;
- empty initial, empty intermediate, empty final, and entirely empty messages;
- one-byte, exact-MessageBytes, and exact-TotalBufferedBytes cases;
- every UTF-8 width split at every byte across initial and continuation frames;
- masked server input and unmasked client input;
- every wire split through headers, mask keys, payloads, fragment boundaries,
  and Unicode scalar boundaries, plus one-byte feeds and empty inputs;
- Ping, Pong, and Close before, between, and after data fragments;
- fragmented, unfragmented, and control frames coalesced into one transport
  input with exact event order;
- final message byte equality and exactly-once delivery.

### Illegal and terminal sequences

- Continuation with no active message, both FIN values and zero/nonzero payload;
- Text or Binary, final or non-final, during active Text and active Binary;
- invalid UTF-8 in the initial, middle, and final fragment;
- a truncated scalar continued legally across frames and truncated again at a
  final continuation;
- EOF at every partial-frame position and between frames while active;
- valid prefix records followed by every failure, proving prefix ordering and
  no offending-frame event;
- reset/release assertions for every failure category and successful finish.

### Numeric boundaries

- MessageBytes zero-message behavior, exact, and +1 accumulated across several
  fragments;
- TotalBufferedBytes exact and +1 for `A + S + P` and duplication peak
  `A + S + P + P`;
- EventQueueEntries exact and +1 for intermediate and final continuations;
- checked-add overflow models for every accumulated-length expression;
- refusal before accumulator length growth, with a retained valid-prefix
  record where applicable.

## Seeded runtime and property coverage

`rust/connection-core/fuzz-seeds/us014/` contains small inert hex schedules for
each transition edge, Text scalar crossing, legal control interleave, each
stable failure, empty message, exact/+1 accumulated limits, prior-valid-prefix
ordering, and reset/double-delivery regressions. A test inventories and replays
every seed through `ConnectionCore::step`; seeds are data, not evidence that a
fuzz engine ran.

Deterministic property tests generate bounded sequences from initial kind,
continuation count, FIN placement, control insertion points, payload schedule,
mask role, and transport chunk schedule. The model predicts transition state,
message bytes, UTF-8 result, and ordered outputs. Runs use fixed domains and
recorded seeds so failures are reproducible. Retained regressions cover stale
state after failure, control-state corruption, per-fragment UTF-8 finishing,
message double delivery, missing accumulated-limit checks, and failure after
emitting an offending frame.

This is ordinary seeded runtime/property coverage. Without an actually
executed external engine it is not called fuzz, mutation, differential, Java,
Autobahn, or formal evidence.

## Implementation handoff

- `rust/connection-core/src/fragment.rs`: private accumulator, transition
  planning, persistent byte accounting, UTF-8 continuation, append/finalize,
  and reset.
- `rust/connection-core/src/frame/decode.rs`: retain sole wire decoder; include
  persistent and all distinct staged record backings in header accounting;
  transfer a finalized accumulator from persistent `A` to staged `S`; call
  fragment plan/feed/commit at the existing header, unmask, and record seams;
  return accepted prefix records on failure.
- `rust/connection-core/src/message.rs`: reuse `TextMessage`, `BinaryMessage`,
  and internal delivery values; add crate-private construction from a finalized
  accumulated `Arc<Vec<u8>>`, with no new public constructor.
- `rust/connection-core/src/connection.rs`: add `FragmentFailure`, wire
  `FailureKind::Fragment`, handle EOF precedence, preserve exact output
  expansion, and ensure all terminal paths reset the decoder/accumulator.
- `rust/connection-core/src/lib.rs`: export only the stable failure value if
  needed by the existing public failure interface; keep the accumulator
  private.
- `rust/connection-core/tests/fragmentation.rs`: interface-level transition,
  ordering, UTF-8, arbitrary chunk, limit, EOF, and release coverage.
- `rust/connection-core/fuzz-seeds/us014/`: inert replay schedules only.
- `evidence/us014-fragmentation.json`: compact source/test receipt with
  `OWNER_ATTESTED_NOT_INDEPENDENT`, no promoted external claims.

## Completion boundary

US-014 is complete when real debug and release gates pass and the shipped
`ConnectionCore` path delivers every legal fragmented Text/Binary message
exactly once, in order, under arbitrary transport chunking and legal control
interleaving; rejects every illegal, invalid, truncated, EOF, over-limit, or
over-event sequence before prohibited growth; and releases all active state on
completion or terminal failure.

Completion makes no Ping/Pong event, automatic response, Close/EOF lifecycle,
outbound fragmentation, Autobahn, live-Java, external fuzz/mutation, formal,
independent-review, signing, publication, production, or release claim.
