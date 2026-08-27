# US-012 canonical frame codec contract

Status: implementation architecture  
Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`  
Claim ceiling: `BOUNDED_TEST_EVIDENCE`

## Scope

US-012 adds the dependency-free RFC 6455 frame codec to the shipped
`websocket_core` crate. It incrementally decodes inbound frames through
`ConnectionCore::step`, exposes a deterministic explicit-key encoder, and
executes finite bounded checks against the exact production mask and header
symbols. It does not deliver messages, enforce fragmentation sequences,
auto-pong, interpret close payloads, perform normal EOF/close behavior, or add
sockets, callbacks, extensions, compression, or ambient randomness.

The physical proof targets are corrected to the shipped workspace while their
fully qualified identities remain fixed:

- `rust/connection-core/src/frame/decode.rs` —
  `websocket_core::frame::decode::FrameHeaderDecoder::decode_header`
- `rust/connection-core/src/frame/mask.rs` —
  `websocket_core::frame::mask::apply_mask_in_place`

Until the conformance, differential, and production consumers land, each
target is `RESOLVED_ACTUAL_SYMBOL_BOUNDED_PENDING_CONSUMERS`, never
`RESOLVED_PRODUCTION_SYMBOL`.

## Public frame vocabulary

- `Opcode`: Continuation, Text, Binary, Close, Ping, Pong.
- `Frame`: immutable FIN/opcode/on-wire-mask/payload observation with getters.
- `OutboundFrame`: borrowed FIN/opcode/payload input.
- `FrameEncoder`: constructed from a checked `ConnectionConfig` and `Role`.
- `EncodedFrame`: immutable owned wire bytes.
- `SemanticEvent::FrameReceived { frame }`: the ordered frame-level seam later
  stories interpret. Emission is not text/binary delivery, fragmentation
  reassembly, ping/pong policy, or close handling.

The encoder takes an explicit optional four-byte client mask key. Client role
requires a key and emits masked bytes; server role forbids a key and emits
unmasked bytes. Existing message/control/close commands remain unavailable to
their owning stories rather than receiving a fixed key or ambient RNG.

## Header decode contract

`FrameHeaderDecoder::decode_header` accepts the checked configuration, role,
already-retained payload bytes, and a prefix. It returns an incomplete minimum
header size or a complete immutable header. Validation order is fixed:

1. fewer than two base bytes is incomplete;
2. reject any RSV bit;
3. reject reserved opcode;
4. reject a non-FIN control opcode;
5. wait for the selected 0/2/8 extended-length bytes;
6. reject a set 64-bit high bit, then noncanonical 16- or 64-bit lengths;
7. reject a control payload over 125;
8. require masked server input and unmasked client input;
9. check header/mask/payload arithmetic, platform conversion, frame cap, and
   retained-plus-payload total cap before allocation;
10. wait for all four mask-key bytes, then complete.

Java's inbound unmasked-frame leniency is recorded as a source-derived quirk;
it cannot weaken the RFC role gate.

## Streaming and allocation

The private decoder retains at most fourteen header bytes in a fixed array.
After a complete, cap-checked header it performs one fallible exact payload
reservation, copies only arrived bytes, and calls the exact mask function for
each newly received range with its prior payload offset. Empty payloads finish
without allocation. Completed frames reset the header state and decoding
continues through any remaining input, so one step can produce several events
or an event followed by a partial frame.

Dynamic accounting includes completed frame payloads staged in the current
result plus the one incomplete payload. No declared payload is reserved before
checked `FrameBytes` and `TotalBufferedBytes` admission. Event emission is
bounded by the configured event-entry limit.

Valid frames leave the connection Open and emit `FrameReceived` in wire order.
A protocol, limit, conversion, or allocation failure closes once and emits no
event for the failing frame. Earlier completed events in the same call remain
ordered before `StateChanged(Closed)`. EOF during a partial header or payload is
a typed frame failure; EOF between frames remains owned by US-016.

## Encoder

The encoder validates opcode, control FIN/length, role/key pairing, canonical
7-/16-/64-bit length selection, checked wire-length arithmetic, platform
conversion, and configured frame/total caps before one fallible reservation.
It calls `apply_mask_in_place` for client payload bytes. It never handles
message typing, fragmentation state, control responses, close codes, or command
queueing.

## Bounded actual-code evidence

`assurance/formal/frame-results.json` records a deterministic finite harness
that calls the two exact production symbols. The closed receipt binds target
paths, SHA-256 values, Git blob IDs, toolchain/Cargo/harness identities, the
eight bounded US-006 frame-obligation results, nonzero per-obligation counts, explicit
bounds and assumptions, good and bad canaries, raw/normalized artifacts, and
two byte-identical semantic replays.

The checked-header-arithmetic obligation remains a future, backend-unavailable
proof target. The ordinary finite tests retain noncanonical-length and high-bit
rejection coverage but do not count those cases as arithmetic proof.

Source-mutation canaries operate only in disposable copies and must kill:
wrong mask index, XOR replacement, removed fragmented
or oversized control checks, removed noncanonical 16-/64-bit checks, removed
64-bit high-bit check, allocation-before-cap, and inverted/removed role masking.
Each retained kill names the changed-source digest, exact obligation, minimized
input, stable counterexample identity, and raw log digest.

This evidence is finite actual-code checking, not Kani, CBMC, unbounded proof,
production refinement, consumer linkage, independent review, publication, or
production approval. Unavailable Kani remains `UNAVAILABLE_BACKEND_BLOCKED`.

## Required tests

- Canonical 0, 1, 124, 125, 126, 127, 65,534, 65,535, and 65,536 payload
  classes, exact headers, round trips, arbitrary cuts, and one-byte feeding.
- All six valid and ten reserved opcodes; each RSV bit; 2×2 role/mask matrix.
- Noncanonical 16/64 forms, 64-bit high bit, control FIN and 125/126 boundary.
- Frame/total/event limits at boundary and +1, multi-frame same-step retained
  accounting, complete-plus-partial tails, and EOF at every header boundary.
- Mask equation and involution for all four offsets, deterministic keys, chunk
  schedules, and the RFC literal example.
- Exact frozen public framing families, inert fuzz seeds, finite actual-symbol
  results, source mutant kills, two identical replays, and hostile evidence
  substitution/zero-count/inflated-claim/dirty-HEAD failures.

## Deferred owners

- US-013: text/binary validation and delivery.
- US-014: continuation sequence and reassembly.
- US-015: ping/pong commands, callbacks, and automatic pong.
- US-016: close payload, close handshake, normal EOF, and protocol close writes.
- US-017: owner scheduling and queue semantics.
- US-018: transport adapter.
