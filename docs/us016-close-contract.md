# US-016 bounded close, EOF, and terminal-state contract

Status: execution-ready architecture at
`8f18f9150cc204c749a713461d2fc51e4d5d68cc`

Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`

Claim ceiling: `BOUNDED_TEST_EVIDENCE`

## Scope and public seam

US-016 completes the RFC 6455 closing lifecycle behind the existing
dependency-free `websocket_core::ConnectionCore` module. The only mutable
protocol seam remains `ConnectionCore::step`. This story adds one explicit
transport fact to that seam so the core does not confuse producing close bytes
with flushing them:

```rust
pub enum CoreInput<'a> {
    Transport(TransportBytes<'a>),
    Command(LocalCommand),
    TransportEof,
    TransportWriteFlushed,
}
```

`TransportWriteFlushed` asserts that every `TransportWrite` returned before
this input has been accepted and drained by the transport adapter. The core
uses it only to confirm its one closing-handshake write. It does not create a
general write queue or count operating-system bytes. In `Connecting` and
`Open`, where earlier stories do not retain write state, it is an idempotent
no-op. In `Closed` it is also an idempotent no-op.

The close slice owns:

- local close payload validation and explicit-key encoding;
- inbound close payload parsing and semantic observation;
- the exact `Open -> Closing -> Closed` state machine;
- peer-first acknowledgement, local-first acknowledgement, and simultaneous
  close behavior;
- the one retained close-write-pending bit and write-flush transition;
- EOF classification in every lifecycle and decoder/fragment condition;
- data and control admission while closing;
- one terminal state notification and complete decoder/fragment reset.

It does not own sockets, shutdown syscalls, clocks, timeouts, callbacks,
reconnect policy, compression, extensions, entropy, a general output queue, or
application scheduling. No wall-clock close timeout is added. A runtime may
feed a future explicit timeout command, but elapsed time is not inferred in the
Sans-I/O kernel.

No Autobahn rerun, live Java execution, external fuzz or mutation engine,
formal backend, signing, publication, production, or independent-review claim
is authorized by this contract. Existing recovered evidence retains its
original provenance and is not promoted into US-016 evidence.

## Architectural decision: one private close module

The existing private `close` placeholder becomes one deep module behind
`ConnectionCore`. Its implementation owns the close-code table, close payload
parser, local payload builder, close-handshake state, transition planning,
admission arithmetic, and terminal/EOF classification. Its interface to
`ConnectionCore` should remain approximately:

1. validate and preflight one local close or peer-close record;
2. return an admitted ordered output plan plus the next private close state;
3. consume a write-flushed or EOF fact and return one transition plan;
4. reset the private close state on terminal failure.

Exact private names may change during TDD. The private module must not expose
a second public state machine, parse WebSocket frame headers, decode masking,
source a client key, or own a transport. `FrameDecoder` remains the sole wire
decoder and `FrameEncoder` remains the sole canonical frame encoder. Public
tests exercise `ConnectionCore::step`; tests do not reach into a public close
parser or planner.

Deleting this module would spread code legality, reason parsing, client-key
rules, acknowledgement matching, pending-write accounting, EOF precedence,
and terminal idempotence across `connection.rs`, `control.rs`, and the frame
decoder. Concentrating those rules behind the existing core seam therefore
adds depth and locality without inventing an adapter seam.

## Primitive Test

The split is deliberate:

| Capability | Atomicity | Bitter Lesson | ZFC | Placement |
|---|---|---|---|---|
| Commit close state, outputs, pending-write state, and reset as one step | Concurrent or partial commit would violate exactly-once state, while the single-owner core makes the operation atomic | A stronger model still needs deterministic runtime state | Pure protocol transport/state | code in the private close module |
| Parse codes/reasons and encode exact wire bytes | One admitted input must have one result | A stronger model still delegates byte validation and encoding | Pure parsing/formatting | code, reusing `FrameEncoder` and UTF-8 machinery |
| Decide the owner-relaxed accepted-code and client-entropy policy | The decision itself has no runtime race | A stronger model can reason about compatibility better | Contains policy judgment | this contract; code only enforces the frozen decision |
| Generate fresh client mask entropy | External entropy state can race and the core has no entropy seam | Quality depends on the runtime and threat model | Environment/policy judgment | caller/runtime, never the core |
| Decide when a close timeout has elapsed or a socket should be aborted | External scheduling owns this fact | A stronger runtime adapter can make the decision with more context | Contains time and operational judgment | caller/runtime; explicit future input only |

The implementation encodes only the frozen protocol transport and atomic
transition table. It does not smuggle timeout, entropy, or deployment judgment
into the kernel.

## Public close command and values

The existing close command gains an optional code and an explicit per-frame
mask key:

```rust
pub enum LocalCommand {
    // existing variants
    Close {
        code: Option<u16>,
        reason: Box<str>,
        mask_key: Option<[u8; 4]>,
    },
}
```

`None` means an empty close payload and therefore requires an empty `reason`.
`Some(code)` encodes the two-byte network-order code followed by the UTF-8
reason bytes. `Box<str>` makes a locally supplied reason valid UTF-8 by type;
the close module still checks its encoded byte length.

For `Role::Client`, `mask_key` is required and consumed for this close frame
only. For `Role::Server`, it is forbidden. The failures remain the existing
`FrameFailure::MissingMaskKey` and `FrameFailure::UnexpectedMaskKey` so all
outbound frames use one role/key vocabulary. The core never creates, stores,
derives, repeats, or certifies a client key. Fresh unpredictable client keys
remain the caller's responsibility exactly as in US-015.

An accepted inbound close adds one immutable semantic observation:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseInitiator {
    Local,
    Peer,
}

pub struct CloseFrame { /* private shared frame payload owner */ }

impl CloseFrame {
    pub fn code(&self) -> Option<u16>;
    pub fn reason(&self) -> &str;
}

pub enum SemanticEvent {
    // existing variants
    CloseReceived {
        close: CloseFrame,
        initiator: CloseInitiator,
    },
}
```

`CloseFrame` clones the decoded `Frame`'s `Arc<Vec<u8>>` backing and stores only
validated offsets/metadata; it does not copy the at-most-125-byte payload.
`CloseInitiator::Local` means this core had already admitted a local close
before the first peer close arrived. `Peer` means the peer close was observed
first. The sequential seam gives simultaneous wire activity a deterministic
classification: whichever input the caller admits first initiates this core's
state machine.

`CoreOutput::StateChanged(Closed)` is the one terminal notification. US-016
does not add a second `Terminated` semantic event that adapters could deliver
twice. `StepResult::failure` carries abnormal terminal detail; the locally
submitted command and `CloseReceived` carry clean close detail.

## Accepted and forbidden close codes

The no-extension owner-relaxed profile accepts this closed set on the wire and
from local commands:

- `1000`, `1001`, `1002`, `1003`, `1007`, `1008`, `1009`, `1011`, `1012`,
  `1013`, and `1014` for either sender role;
- `1010` only when the sender is a client: a local client may send it and a
  server core may receive it;
- application/private codes `3000..=4999` for either sender role.

The profile rejects:

- `0..=999` and `5000..=65535` as outside the wire range;
- `1004`, `1005`, `1006`, and `1015` as forbidden wire sentinels/reservations;
- `1010` from a server sender, including a local server command or an inbound
  server-to-client frame;
- `1016..=2999` because no extension or later protocol that assigns those
  reserved values is negotiated by this core.

This is a deliberate bounded compatibility set, not a claim that every future
IANA assignment is permanently invalid. Adding a future assigned code changes
the frozen table and its tests; it must not be accepted by a broad numeric
range accidentally.

The stable vocabulary is implementation-ready:

```rust
pub enum CloseCodeRejection {
    OutsideWireRange,
    ForbiddenWireCode,
    WrongSenderRole,
    UnassignedOrExtensionReserved,
}

pub enum CloseFailure {
    PayloadLengthOne,
    ReasonWithoutCode,
    InvalidCode {
        code: u16,
        rejection: CloseCodeRejection,
    },
    InvalidReason(Utf8Failure),
    DuplicateLocalClose,
    DuplicatePeerClose,
    AcknowledgementMismatch,
    DataAfterClose { opcode: Opcode },
    TrailingBytesAfterClose,
    UnexpectedEofOpen,
    EofBeforePeerClose,
    EofBeforeAcknowledgement,
    EofBeforeCloseWriteFlushed,
}
```

`CloseFailure` remains `#[non_exhaustive]`. Exact variant spelling may be
adjusted once in the RED interface scaffold, but the distinctions and state
effects in this contract may not be collapsed.

## Payload grammar and failure precedence

An inbound structurally valid Close frame is interpreted as follows:

| Payload length | Meaning |
|---|---|
| `0` | no code, empty reason |
| `1` | `CloseFailure::PayloadLengthOne` |
| `2..=125` | first two bytes are a network-order code; remaining bytes are the reason |

For a payload of two or more bytes, code legality is checked before reason
UTF-8. The reason is validated as strict canonical UTF-8 using the existing
US-013 validator semantics. Invalid leading/continuation bytes, overlong
forms, surrogates, out-of-range scalars, and truncated final scalars map to
`CloseFailure::InvalidReason(Utf8Failure)` with offsets relative to the first
reason byte. No lossy conversion or replacement character is permitted.

Local payload rules are checked in this order:

1. lifecycle and acknowledgement-mode legality;
2. `None` requires an empty reason;
3. sender-role/code legality;
4. `Some(code)` plus reason must be at most 125 bytes, so the reason is at most
   123 encoded bytes;
5. one write-entry admission;
6. explicit mask-key role check and checked wire-length/total-byte preflight;
7. bounded close-payload allocation, followed by canonical frame allocation.

A local validation, limit, backpressure, arithmetic, role/key, or allocation
failure returns no output and leaves state and private close facts unchanged.
The caller's `Box<str>` allocation occurred before the seam and is not counted
as core retention.

Inbound failure precedence is:

1. US-012 frame syntax/masking/canonical-length/125-byte validation;
2. current closing-state record legality and duplicate detection;
3. close payload length;
4. code range/reservation/sender role;
5. strict reason UTF-8;
6. event/write/total-byte admission and checked arithmetic;
7. output and automatic-echo allocation.

An inbound failure is terminal. The offending frame produces no
`FrameReceived` or `CloseReceived`; all earlier accepted record groups remain
in wire order, followed by exactly one `StateChanged(Closed)`. The decoder,
fragment accumulator, UTF-8 state, and close planner are reset. A valid peer
close that requires an automatic server echo is one indivisible admitted
group: if the echo cannot be admitted or allocated, none of that close's
semantic outputs are exposed.

## Private close-handshake state

The private close module retains only bounded facts:

```text
initiator: None | Local | Peer
local_close: None | admitted code/reason identity
peer_close: None | shared validated CloseFrame
close_write_pending: bool
```

It does not retain general transport writes. At most one close write is
admitted for a connection. The locally initiated code/reason identity is at
most 125 bytes; the peer value shares the already bounded frame owner. The
state satisfies:

```text
Connecting: no close facts
Open:       no close facts
Closing:    at least local_close or peer_close exists
Closed:     close facts may be inspected only while constructing the terminal result
```

Entering `Closing` immediately abandons and resets any partial data frame,
fragment accumulator, and incremental text validator. A Close frame may
legally interleave during fragmentation, but no incomplete application message
survives the transition. The close module never creates a second fragment
state.

## Exact local-close behavior

An accepted local close in `Open` emits:

```text
TransportWrite(Close(code/reason, explicit role-correct masking))
StateChanged(Closing)
```

The core records `initiator = Local`, records the admitted local close, marks
the close write pending, resets decoder/fragment state, and becomes `Closing`.
It does not emit `CloseReceived`, because no peer close was observed.

`TransportWriteFlushed` while only the local close has been sent clears the
pending bit and emits nothing; the core remains `Closing` until it observes a
peer close. A subsequent valid peer close is the acknowledgement and emits:

```text
SemanticEvent::FrameReceived(peer_close_frame)
SemanticEvent::CloseReceived(peer_close, Local)
StateChanged(Closed)  // only if the local close write was already flushed
```

If the peer close arrives before the local write is confirmed flushed, the
same two semantic events are emitted and the core stays `Closing`. The later
`TransportWriteFlushed` emits exactly one `StateChanged(Closed)`.

The peer acknowledgement need not repeat the locally selected code/reason.
Any valid peer Close completes the receive half. This covers simultaneous
close: each endpoint's already-sent local close is acknowledged by the other
valid close, and neither sends a second close frame.

A second local Close after one was admitted returns
`CloseFailure::DuplicateLocalClose`, no output, and leaves `Closing` unchanged.

## Exact peer-first close and acknowledgement behavior

For a valid Close received in `Open`, both roles first emit:

```text
SemanticEvent::FrameReceived(peer_close_frame)
SemanticEvent::CloseReceived(peer_close, Peer)
StateChanged(Closing)
```

The core records `initiator = Peer`, resets decoder/fragment state, and admits
no later application data.

For a server core, the same step automatically appends an unmasked,
byte-identical Close response:

```text
TransportWrite(exact peer close payload)
```

The server remains `Closing` with its one close write pending. A later
`TransportWriteFlushed` emits exactly one `StateChanged(Closed)`.

For a client core, the transport input contains no safe fresh mask key, so the
core does not fabricate an acknowledgement. The caller must next submit:

```rust
LocalCommand::Close {
    code: peer.code(),
    reason: peer.reason().into(),
    mask_key: Some(fresh_unpredictable_key),
}
```

This is the same explicit-entropy decision as US-015 automatic Pong. In this
peer-first `Closing` state only, a local Close is treated as the required
acknowledgement. Its code and reason must be byte-identical to the first peer
close; otherwise `AcknowledgementMismatch` is nonterminal with no output. An
accepted acknowledgement emits one masked `TransportWrite`, marks the write
pending, and stays `Closing`. `TransportWriteFlushed` then emits exactly one
`StateChanged(Closed)`.

A second peer Close before terminal completion is
`CloseFailure::DuplicatePeerClose` and is terminal. Once `Closed`, transport
bytes are rejected by the existing `InvalidState` rule and cannot produce a
second close observation or terminal state change.

## Data and Ping/Pong behavior in Closing

While `Closing`:

- inbound Close is handled only as the first peer close described above;
- inbound Ping and Pong remain structurally validated and emit their existing
  `FrameReceived` then `Ping`/`Pong` observations in wire order;
- automatic Pong is disabled, even for `ServerOnly`, so no non-close write is
  introduced after closing begins;
- inbound Text, Binary, or Continuation fails terminally as
  `CloseFailure::DataAfterClose { opcode }`, without emitting the offending
  frame or message;
- local `SendText`, `SendBinary`, `SendPing`, and `SendPong` fail
  nonterminally with `InvalidState { input: LocalCommand, state: Closing }`;
- `StartClientHandshake` is likewise invalid and nonterminal;
- only the peer-first client acknowledgement form of local `Close` is
  accepted.

If a transport input contains a valid Close followed by any further complete
frame or undecodable trailing bytes, the Close observation and any required
close write remain in order, the trailing bytes produce
`CloseFailure::DataAfterClose` or `TrailingBytesAfterClose`, and terminal
cleanup emits `StateChanged(Closed)` only if it has not already been emitted.
No record after the first Close produces a semantic observation.

## EOF behavior

EOF never fabricates a Close frame because the transport can no longer carry
it. EOF terminal failures emit no semantic frame and exactly one
`StateChanged(Closed)`.

| State/facts at EOF | Result |
|---|---|
| `Connecting`, incomplete client response or server request | existing `HandshakeFailure::UnexpectedEof`; reset and close once |
| `Open`, decoder has a partial frame | existing `FrameFailure::UnexpectedEof`; it takes precedence over fragment state |
| `Open`, between frames with active fragmented message | existing `FragmentFailure::UnexpectedEof` with opcode/accumulated bytes |
| `Open`, between frames with no fragment | `CloseFailure::UnexpectedEofOpen` (abnormal no-close EOF) |
| `Closing`, local close sent but no peer close | `CloseFailure::EofBeforePeerClose` |
| `Closing`, peer close received but client acknowledgement not sent | `CloseFailure::EofBeforeAcknowledgement` |
| `Closing`, both close frames accounted for but local close write remains pending | `CloseFailure::EofBeforeCloseWriteFlushed` |
| `Closed` | idempotent no-op with no failure or output |

Successful entry to `Closing` already reset partial frame/fragment state, so a
Closing EOF cannot also report the abandoned pre-close fragment. Before any
close transition, partial-frame failure wins over fragment EOF because the
active frame must finish before a continuation sequence boundary can be known.

Previously returned `TransportWrite` values are owned obligations of the
caller. EOF does not retract, mutate, or re-emit them. An adapter must process
outputs in order, drain the close write, then feed `TransportWriteFlushed`.
Feeding EOF first truthfully produces the pending-write failure. The core does
not claim a clean two-way handshake from write construction alone.

## Exactly-once state and reset rules

`StateChanged(Closing)` occurs at most once: on the first admitted local or
peer close. `StateChanged(Closed)` occurs at most once: either when both close
halves exist and the local close write is flushed, or on the first terminal
failure/EOF.

After `Closed`:

- `TransportEof` and `TransportWriteFlushed` are idempotent no-ops;
- transport bytes and local commands return the existing typed `InvalidState`
  failure with no output;
- no close, frame, message, Ping, Pong, or state event can recur;
- the frame decoder, fragment accumulator, UTF-8 validator, handshake parser,
  and private close state retain no reusable protocol bytes.

All terminal helpers must consult or structurally guarantee the one-shot
state transition rather than blindly appending `StateChanged(Closed)`. A
terminal failure after earlier valid records preserves their complete output
groups, then appends the terminal state once. No error path may transition
`Closed -> Closed` observably.

## Admission, backpressure, and allocation

The close planner performs two passes before exposing an input's first new
close semantic output:

1. walk decoded records in wire order, validate close semantics and Closing
   legality, identify the accepted prefix, count semantic events, state
   outputs, close writes, encoded bytes, and terminal outcome with checked
   arithmetic;
2. reserve the complete `CoreOutput` vector and encode each already-admitted
   close write, then commit outputs and close state in order.

One inbound Close consumes two semantic event entries (`FrameReceived` and
`CloseReceived`). Ping/Pong retain the US-015 two-event count. A server
peer-first close or any local Close consumes one write entry. State-change
outputs are included in output-vector capacity but not in the semantic-event
queue limit. Encoded close wire bytes participate in
`total_buffered_bytes`, including the four-byte client mask key when present.

The 125-byte protocol cap is checked before allocation. All additions and
wire-length computations are checked. Event backpressure, write
backpressure, total-buffer refusal, arithmetic overflow, and allocation
failure occur before the offending close group is visible. Earlier groups in
the same input remain visible only when their own resources were completely
admitted.

Local failure is nonterminal and atomic. Inbound resource failure is terminal
under the current owner-relaxed core, clears all state, and does not attempt a
best-effort Close write whose own resources were not admitted. No allocation
failure is converted to panic.

## TDD seams and bounded evidence

The confirmed public test seams are:

```rust
ConnectionCore::step(CoreInput::Command(LocalCommand::Close { .. }))
ConnectionCore::step(CoreInput::Transport(_))
ConnectionCore::step(CoreInput::TransportWriteFlushed)
ConnectionCore::step(CoreInput::TransportEof)
ConnectionCore::state()
StepResult::{outputs, failure, state}
```

RED must first prove the placeholder behavior is unavailable or lacks the
new interface. Implementation then proceeds in vertical slices:

1. local server/client close validation and encoding;
2. peer-close parsing and semantic observation;
3. local-first and simultaneous acknowledgement;
4. peer-first server echo and client explicit-key acknowledgement;
5. write-flush completion and exactly-once terminal state;
6. Closing data/control rules;
7. EOF precedence and state reset;
8. limits, allocation injection, arbitrary chunks, and valid-prefix batches.

Bounded tests cover at minimum:

- empty payload and every accepted/frozen-rejected code class for both sender
  roles;
- empty, 123-byte, and over-123-byte reasons, including multibyte boundaries;
- one-byte payload and every strict UTF-8 failure class at every byte split;
- client missing/reused-by-caller-observable key cases and server unexpected
  key, without claiming the core proves entropy freshness;
- local-first, peer-first, and simultaneous close with flush before/after peer
  close and every exact output order;
- peer-first client exact acknowledgement and mismatch;
- duplicate local/peer close windows and all Closed-state idempotence rules;
- Ping/Pong and every application opcode during Closing;
- Close interleaved before/during/after fragmentation, proving immediate
  release and no stale delivery;
- EOF in Connecting/Open/Closing/Closed, every partial-frame byte position,
  active fragments, missing ack, missing peer close, and pending write;
- event/write/total limits, arithmetic and injected allocation refusal;
- a valid prefix before malformed close, Close before trailing records, and
  arbitrary transport chunking of all cases.

Inert retained regression seeds cover wrong-code acceptance, missing
acknowledgement, data-after-close delivery, duplicate terminal notification,
premature Closed before write flush, and stale fragment delivery. Tests must
actually replay each seed through the shipped `ConnectionCore::step` path;
syntax-only seed inspection is not execution evidence.

Deterministic model-table tests may enumerate bounded action sequences and
assert state/output/failure invariants. They are ordinary systematic tests.
They must not be labeled temporal proof or formal verification. A future
external formal result remains a separately provenance-bound proved-model
artifact and cannot establish the Rust implementation without a reviewed
composition/refinement link.

## Planned implementation map

- `rust/connection-core/src/close.rs`: implement the private parser, code
  table, close value, planner, encoder coordination, state facts, and EOF/flush
  transition table.
- `rust/connection-core/src/connection.rs`: add the public command key/code
  shape, `TransportWriteFlushed`, semantic close observation and stable failure
  vocabulary; route Close records and Closing inputs through the close module;
  make terminal transition one-shot.
- `rust/connection-core/src/control.rs`: parameterize batch planning by
  lifecycle so Closing Ping/Pong are observation-only and Close groups are
  delegated exactly once; do not create a second close parser.
- `rust/connection-core/src/lib.rs`: export only the stable public close values
  already carried through the ConnectionCore interface.
- `rust/connection-core/tests/close_eof.rs`: add the primary public-seam state,
  order, code/reason, key, flush, EOF, limit, allocation, and seed tests.
- Existing connection/frame/message/fragment/control tests: update only
  expired placeholder expectations or add focused cross-story regressions.
- `rust/connection-core/fuzz-seeds/us016/`: retain inert bounded seeds replayed
  by the Rust tests.
- `evidence/us016-close.json`: bind exact sources, tests, deterministic counts,
  toolchain, and bounded nonclaims after implementation.

## Owner-relaxed done boundary

US-016 is complete when the shipped dependency-free `ConnectionCore` parses,
emits, acknowledges, flush-confirms, and terminates the bounded close state
machine exactly as above; rejects every malformed, forbidden, duplicate,
post-close-data, limit, allocation, and EOF path with stable typed outcomes;
releases partial frame/fragment/text state; and passes debug/release public-seam
tests plus the parent repository gates.

Completion does not claim Autobahn category 7 execution, live Java parity,
external fuzz/mutation/formal execution, temporal proof, client entropy
quality, wall-clock timeout behavior, socket shutdown correctness, independent
review, signing, publication, or production readiness.
