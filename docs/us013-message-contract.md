# US-013 strict message-delivery contract

Status: execution-ready architecture at
`8e5b19b4015af159e3f26906556fe4ac697c8af5`  
Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`  
Claim ceiling: `BOUNDED_TEST_EVIDENCE`

## Scope

US-013 deepens the existing dependency-free `websocket_core::ConnectionCore`
module at its sole mutable seam:

```rust
ConnectionCore::step(CoreInput::Transport(_)) -> StepResult
```

It delivers only complete, unfragmented (`FIN = true`) Text and Binary frames.
The frame event remains observable and precedes the corresponding typed
message event. Text is delivered only after strict UTF-8 validation over the
newly unmasked payload slices as transport bytes arrive. Binary is delivered
byte-for-byte without interpretation.

US-013 does not start or append fragmented messages, validate fragmented text,
reject orphan continuations, interleave control frames with fragment state, or
apply whole-fragmented-message limits. Those behaviors remain US-014. It does
not implement ping/pong, close frames, normal EOF, sockets, callbacks,
extensions, compression, or runtime ownership.

`LocalCommand::SendText` and `LocalCommand::SendBinary` remain
`ProtocolSliceUnavailable { owner_story: ProtocolStory::Messages }`. A client
write needs an explicit fresh masking key and owner scheduling; US-013 does not
invent ambient randomness or a temporary deterministic key.

No Autobahn rerun, live Java execution, Kani/formal backend, signing,
publication, production claim, new dependency, `unsafe`, `build.rs`, or proc
macro is authorized. Existing source-derived Java observations and recovered
Autobahn results may be referenced, but not promoted into new executions.

## Architectural decision

`ConnectionCore` remains the only public protocol module. US-013 adds private
`message` and `utf8` implementations rather than a public parser or callback
interface. Deleting these implementations would force UTF-8 streaming state,
message admission, delivery typing, and ordering back into the frame decoder
and caller; their depth therefore creates locality without adding another
public seam.

The frame decoder and message implementation have one private coordination
point. This is an internal implementation relationship, not a hypothetical
adapter seam:

1. after a complete canonical header and before payload reservation, message
   admission reports the required semantic-event count and validates the
   single-frame message cap;
2. after each newly arrived payload range is unmasked, the frame decoder feeds
   that exact range to the active UTF-8 validator when applicable;
3. at complete payload, message finalization returns either a typed delivery
   marker or a typed failure;
4. the connection core expands one successful decoded record into ordered
   public outputs.

There is no second frame decoder, message accumulator, public UTF-8 validator,
or copied protocol state.

## Public values and output order

The existing `Frame` getters remain source-compatible. Its private payload
owner changes from `Box<[u8]>` to a standard-library `Arc<Vec<u8>>`. The
decoder moves its already-reserved `Vec<u8>` directly into that owner, so no
second payload-sized allocation or byte copy occurs; the frame and message
observations then share that one immutable byte backing. The Arc and Vec are
never exposed as synchronization or mutation policy; callers receive only
borrowed views from deep value types.

```rust
pub struct TextMessage { /* shared, already-validated UTF-8 bytes */ }
impl TextMessage {
    pub fn as_str(&self) -> &str;
    pub fn as_bytes(&self) -> &[u8];
}

pub struct BinaryMessage { /* shared uninterpreted bytes */ }
impl BinaryMessage {
    pub fn as_slice(&self) -> &[u8];
}

pub enum SemanticEvent {
    // existing handshake events
    FrameReceived { frame: Frame },
    Text { message: TextMessage },
    Binary { message: BinaryMessage },
}
```

`TextMessage` has no public unchecked constructor. Its `as_str` invariant is
established by the private validator before construction. `BinaryMessage`
preserves every octet, including NUL and non-UTF-8 bytes. Both message values
clone only the `Arc<Vec<u8>>` owner; neither reallocates or copies the payload.

For every valid final data frame the exact normalized order is:

```text
FrameReceived(frame)
Text(message) | Binary(message)
```

Several frames in one input repeat that pair in wire order. A failure in a
later frame preserves all earlier completed outputs, followed by
`StateChanged(Closed)`. The offending final Text frame emits neither a frame
nor a message event if its UTF-8 validation fails. This rule is invariant under
transport chunking, including when the first invalid byte arrives before the
declared payload is complete.

## Exact admission and allocation order

For a `FIN = true` Text or Binary header, admission occurs before payload
reservation in this order:

1. all existing US-012 canonical header, role-mask, FrameBytes, and
   TotalBufferedBytes checks;
2. checked conversion and `payload_length <= MessageBytes`;
3. checked addition of two required semantic-event slots to the batch's
   already-staged event count, bounded by `EventQueueEntries`;
4. one fallible exact payload reservation;
5. incremental payload copy/unmask/validation.

At completion the reserved `Vec<u8>` is moved into `Arc<Vec<u8>>`; only the Arc
control block is added, while the fallibly reserved payload backing and its
bytes stay in place.

The decoder pre-admits two event entries because successful final data always
emits both `FrameReceived` and Text/Binary. A cap of one therefore rejects a
final data header before payload growth. Earlier staged events remain ordered
before the terminal state change. Non-final data, Continuation, and control
frames reserve one frame-event slot and retain US-012 behavior.

The shared Vec payload backing is counted once. `MessageBytes` bounds one
unfragmented message; `FrameBytes` still bounds its frame;
`TotalBufferedBytes` includes the one shared payload and every earlier payload
staged in the current result. Every length addition and conversion is checked.
Zero-length messages are valid. Exact limits succeed; boundary plus one fails
before payload allocation.

`ConnectionConfig` gains only a crate-private checked `message_bytes()` getter.
No adapter-local cap or new configuration value is introduced.

## Incremental strict UTF-8

The private `Utf8Validator` has fixed-size scalar state only: absolute byte
offset, remaining continuation count, and the allowed range for the next byte.
It accepts slices in order and never allocates. The frame decoder invokes it
after masking is removed from each newly copied range, so a code point split at
any wire/transport boundary is checked as one sequence.

The state machine accepts exactly:

- ASCII `00..7f`;
- `c2..df` followed by one `80..bf` byte;
- `e0` followed by `a0..bf`, then `80..bf`;
- `e1..ec` or `ee..ef` followed by two `80..bf` bytes;
- `ed` followed by `80..9f`, then `80..bf`;
- `f0` followed by `90..bf`, then two `80..bf` bytes;
- `f1..f3` followed by three `80..bf` bytes;
- `f4` followed by `80..8f`, then two `80..bf` bytes.

Those ranges reject overlong encodings, UTF-16 surrogate code points, values
above U+10FFFF, stray continuation bytes, forbidden lead bytes, malformed
continuations, and every other noncanonical sequence. Finalization succeeds
only with zero remaining continuations; otherwise it reports truncation.

Validation is active only while decoding a `FIN = true`, `Opcode::Text` frame.
It is inactive for Binary, control frames, Continuation, and every non-final
Text/Binary frame. In particular, US-013 must not reject an incomplete Unicode
sequence at the end of a non-final Text frame; US-014 will preserve validator
state across continuations.

## Stable failures and state effect

`Utf8Failure` becomes populated with stable structured categories and an
absolute byte offset:

```rust
pub enum Utf8Failure {
    UnexpectedContinuation { offset: u64, byte: u8 },
    InvalidLeadingByte { offset: u64, byte: u8 },
    InvalidContinuation { offset: u64, byte: u8 },
    OverlongEncoding { offset: u64 },
    SurrogateCodePoint { offset: u64 },
    CodePointOutOfRange { offset: u64 },
    TruncatedSequence { length: u64, remaining: u8 },
}
```

Exact field names may be mechanically adjusted during TDD, but the distinct
categories, absolute offsets, and equality-stable data are contract. Every
variant maps to RFC invalid-payload close code 1007. US-013 reports
`FailureKind::Utf8` and transitions once to Closed, with the final
`StateChanged(Closed)` output. It emits no close wire frame because US-016 owns
close-frame construction and Closing-state behavior. A `MessageBytes` failure
uses the existing `LimitExceeded` vocabulary; event-cap refusal uses
`Backpressure(QueueKind::Event)`.

On every UTF-8, limit, event, or allocation failure, frame and validator state
reset before the terminal result. There is no stale state for a later call,
although Closed-state admission already prevents reuse.

## US-014 seam

US-014 extends the private message implementation; it does not replace the
US-013 public values or output rules. The reserved behavior is explicit:

| Inbound frame in US-013 | US-013 behavior | US-014 responsibility |
| --- | --- | --- |
| `FIN Text` | strict streaming UTF-8, Frame then Text | unchanged |
| `FIN Binary` | Frame then Binary | unchanged |
| non-final Text/Binary | Frame only | begin one fragment sequence |
| any Continuation | Frame only | require/append/finalize active sequence |
| control frame | Frame only | preserve active fragment state while later control stories act |
| EOF between frames | unavailable to US-016 | fail/reset an active fragment sequence |

The private validator must therefore support reset and continued feeding, but
US-013 never persists it beyond one final Text frame. No placeholder fragment
enum or accumulator is added early.

## TDD matrix

Implementation is test-first through `ConnectionCore::step`, never by testing
a public parser that callers cannot use.

### Valid delivery

- empty, one-byte, and exact-MessageBytes Text and Binary;
- Binary containing all 256 octets, preserved byte-for-byte;
- ASCII plus canonical 2-, 3-, and 4-byte UTF-8, including U+0000, U+007F,
  U+0080, U+07FF, U+0800, U+D7FF, U+E000, U+FFFF, U+10000, and U+10FFFF;
- masked server input and unmasked client input;
- every split before, within, and after frame header, mask key, payload, and
  every byte of each multibyte code point;
- one-byte feeding, empty chunks between every byte, and several final data
  frames in one input;
- exact event order, shared Arc pointer identity, and retained Vec backing with
  no duplicate byte allocation.

### Strict rejection

- stray `80` and `bf` continuation bytes;
- forbidden `c0`, `c1`, and `f5..ff` leads;
- overlong 2-, 3-, and 4-byte forms;
- `ed a0 80` through `ed bf bf` surrogate encodings;
- `f4 90 80 80` and higher out-of-range values;
- missing, non-continuation, and excess continuation bytes;
- truncated 2-, 3-, and 4-byte sequences at final payload completion;
- the same invalid vectors at every transport split and under masking;
- one valid frame followed by one invalid frame in the same input, preserving
  only the valid pair before terminal closure.

### Limits and story separation

- MessageBytes at exact boundary and +1, where +1 fails before reservation;
- TotalBufferedBytes exact and +1 across multiple staged frames;
- EventQueueEntries 1 (reject final data), 2 (one exact pair), and accumulated
  exact/+1 across mixed control and data frames;
- zero-length delivery at minimum valid limits;
- non-final Text ending with an incomplete Unicode prefix emits Frame only and
  does not produce UTF-8 failure;
- non-final Binary and all Continuation frames emit Frame only;
- SendText and SendBinary remain unavailable without writes or state changes;
- partial-frame EOF remains US-012, between-frame EOF remains US-016.

## Fuzz seeds and minimal truthful evidence

`rust/connection-core/fuzz-seeds/us013/` retains a small canonical hex seed for
each valid UTF-8 width, each invalid category, truncation, exact/+1 message
limits, event-cap refusal, multi-frame order, and a non-final Text prefix. The
integration test inventory parses and replays every seed through the shipped
`ConnectionCore::step` path; seed files are data, never executable fixtures.

The neutral scenario table records RFC verdict, role, chunk schedule, expected
ordered events, failure category, and the existing source-derived Java
observation where one exists. Java results are labeled
`SOURCE_DERIVED_NO_LIVE_EXECUTION`; recovered Autobahn category 1/6 references
are labeled `REUSED_NO_RERUN`. Unknown Java observations remain unknown rather
than fabricated agreement.

The story needs only:

- the architecture document;
- production source plus `rust/connection-core/tests/messages.rs`;
- replayed inert US-013 seeds and a compact frozen scenario table;
- ordinary debug/release/fmt/Clippy gates and their actual counts;
- one bounded comments-only review, fixing only blocking correctness/security
  findings.

It does not create a new proof backend, mutation framework, signing hierarchy,
large evidence DAG, or claimed fuzz campaign. Seeded regressions for UTF-8
leniency, event reversal, truncation acceptance, and missing pre-allocation
limits are retained as ordinary executable tests. Any optional fuzz entry point
must call `ConnectionCore::step`; without an executed fuzz engine it is named a
replay seed interface, not fuzz evidence.

## Implementation seams

- `rust/connection-core/src/utf8.rs`: private fixed-state strict validator.
- `rust/connection-core/src/message.rs`: private admission/delivery logic plus
  public deep TextMessage/BinaryMessage values.
- `rust/connection-core/src/frame/mod.rs`: private `Arc<Vec<u8>>` payload owner
  retaining the decoder's reserved Vec backing; existing Frame getters
  unchanged.
- `rust/connection-core/src/frame/decode.rs`: header-time message/event
  admission and per-unmasked-range validator feeding.
- `rust/connection-core/src/connection.rs`: message limit getter, populated
  UTF-8 failures, new semantic events, exact output expansion and failure
  ordering.
- `rust/connection-core/src/lib.rs`: re-export only the two public message
  values; UTF-8 implementation remains private.
- `rust/connection-core/tests/messages.rs`: full interface/e2e matrix.
- `rust/connection-core/fuzz-seeds/us013/`: inert replay inventory.

## Completion boundary

US-013 is complete only when the real debug and release workspace gates pass
and every valid final Text/Binary frame produces exactly Frame then typed
message under arbitrary transport chunking, while every invalid, over-limit,
or over-event input fails deterministically before prohibited growth. Passing
US-013 makes no fragmentation, outbound message, Java parity, Autobahn rerun,
formal proof, independent review, production, publication, or release claim.
