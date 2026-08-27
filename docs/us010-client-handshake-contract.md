# US-010 client opening-handshake contract

Status: implementation-ready architecture for the client opening-handshake
slice. This design is bounded to US-010. Server request validation/response
generation remains US-011; frame and application-data behavior remains
unavailable until US-012 and later stories.

Assurance remains `OWNER_ATTESTED_NOT_INDEPENDENT` and
`independent_review_claimed:false`. This design authorizes no Autobahn rerun,
publication, production mutation, new dependency, `build.rs`, proc macro, or
sbx action.

## Reconciled baseline

The implementation starts from `websocket_core` at
`8f96b4a85a79ec00eeb380bf248ef3b79e35b58f`, not the stale `ws_core` and
`crates/websocket-core` names in early planning artifacts. The physical crate
remains `rust/connection-core`; its package and library identities remain
`websocket-core` and `websocket_core`.

US-009 already provides the only mutating seam,
`ConnectionCore::step(CoreInput) -> StepResult`, immutable checked config,
ordered outputs, typed failures, and a single owner. US-010 deepens that module
instead of adding a second state machine or a public parser. Sockets, clocks,
random generators, callbacks, and Java-shaped handshake builders remain
outside the core.

The frozen handshake corpus has 49 public cases:

- 39 `client_request` cases primarily owned by server-handshake US-011;
- 10 `server_response` cases directly owned by US-010: three valid responses,
  three non-101 statuses, one missing accept, two accept mismatches, and one
  missing Upgrade header.

Those ten are necessary but not sufficient for US-010. The client projection
must add RFC-derived public vectors for every response rule below without
rewriting or weakening the frozen 49-case artifact. All split-point expansion
is generated during tests, not stored as thousands of duplicated vectors.

Relevant existing evidence is:

- `corpora/handshake/cases.jsonl` and `corpora/handshake/manifest.json`;
- `internal/corpora/handshake.go` and
  `docs/us005-handshake-verdict-mapping.md`;
- `evidence/us005-handshake-live-mapping.json`;
- `evidence/intake/semantic-id-migration-map.json` (17 Java rows touch
  US-010, but only `websocket_core::ConnectionCore` currently resolves);
- `evidence/intake/compatibility-surface.json`, surface
  `surface.handshake.client-request` and obligation
  `cutover.surface-handshake-client-request`;
- `evidence/intake/port-seam-dossier.json`, which assigns the client
  handshake and the randomness seam to US-010;
- `evidence/java/behavior-delta-ledger.json`, currently a valid empty ledger;
- `evidence/intake/cutover-contract.json`, especially
  `EXCLUDED_EXTENSION_SUBPROTOCOL_PARITY` and
  `EXCLUDED_RFC_7692_PERMESSAGE_DEFLATE`.

## Authority and deliberate deltas

Behavior decisions keep the established priority:

1. RFC 6455 and directly applicable HTTP RFC requirements;
2. the independent RFC-derived corpus;
3. Java-WebSocket v1.6.0 differential observations.

Autobahn 25.10.1 has no registered opening-handshake category-0 cases and is
not rerun. Java observations calibrate the differential adapter; they do not
override the RFC. In particular, the Rust implementation does not copy Java's
duplicate-field joining, unbounded handshake buffering, permissive header-name
handling, or negotiation behavior.

When the corresponding Java/RFC cases are executed, the implementation appends
hash-chained `rfc-governs` records under these exact subject references:

- `semantic:handshake.client-response.strict-http:provisional-v1` for line,
  header-name, and duplicate-field strictness;
- `semantic:handshake.client-response.bounds:provisional-v1` for total,
  header-count, and header-line enforcement absent in Java;
- `semantic:handshake.client-response.no-negotiation:provisional-v1` for
  rejecting every extension and every undeclared subprotocol.

The ledger writer derives each `delta_id` from canonical record bytes; nobody
invents a digest. Because the current 1.0.0 schema requires a nonempty Autobahn
reference even where Autobahn has no applicable category, the implementation
must evolve the schema rather than cite an unrelated Autobahn case. The new
record form explicitly states `NO_REGISTERED_CATEGORY_0_AT_PIN` and zero
Autobahn executions.

## One public seam

The caller supplies a validated resource descriptor and the exact 16-byte
nonce, then submits one new command through the existing `step` interface:

```rust
pub struct ClientRequestDescriptor { /* private owned fields */ }

impl ClientRequestDescriptor {
    pub fn try_new(
        request_target: &str,
        host: &str,
    ) -> Result<Self, ClientRequestDescriptorError>;
    pub fn request_target(&self) -> &str;
    pub fn host(&self) -> &str;
}

pub enum LocalCommand {
    StartClientHandshake {
        descriptor: ClientRequestDescriptor,
        nonce: [u8; 16],
    },
    // existing later-story commands
}

pub enum SemanticEvent {
    ClientHandshakeOpened {
        descriptor: ClientRequestDescriptor,
    },
}
```

There is no public HTTP parser, SHA-1 object, Base64 encoder, header map,
randomness trait, handshake builder, extension list, or subprotocol list.
The exact `[u8; 16]` is the promoted randomness seam: production adapters may
obtain those bytes from an approved source later, while tests inject fixed
bytes. The core never reads ambient randomness.

`ClientRequestDescriptor::try_new` accepts only an origin-form request target
beginning with `/` and a nonempty Host field value. Both must be ASCII and may
contain no CR, LF, NUL, SP/control injection, or noncanonical line content.
It checks hard-ceiling lengths before copying. The core rechecks the serialized
request against its own possibly smaller config, so a descriptor validated
elsewhere cannot bypass the receiving core's limits. Host/URI/TLS resolution
is an adapter concern; this type owns only the two RFC wire fields.

The cutover contract excludes an extension/subprotocol negotiation framework.
Accordingly the request advertises neither header and the public descriptor has
no negotiation fields. Any response containing `Sec-WebSocket-Extensions` or
`Sec-WebSocket-Protocol`, including an empty value, is rejected. A future
scope decision must introduce a separate story rather than silently widening
this interface.

## Canonical request

For descriptor `request_target`, `host`, and nonce `N`, the private client
module emits exactly:

```text
GET {request_target} HTTP/1.1\r\n
Host: {host}\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Key: {base64(N)}\r\n
Sec-WebSocket-Version: 13\r\n
\r\n
```

Header spelling, order, single SP after `:`, and terminal CRLF are canonical
and deterministic. The known RFC example remains a required vector:
`dGhlIHNhbXBsZSBub25jZQ==` produces
`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` after the RFC GUID derivation.

Request length, each line length including CRLF, and the six header lines are
checked with fallible arithmetic against config before the transport write is
allocated. Failure emits no partial request.

## Dependency-free Base64 and SHA-1

SHA-1 here is the RFC 6455 handshake transform, not a general security choice.
The core stays dependency-free:

- a private fixed-size encoder maps `[u8; 16]` to the canonical 24-byte padded
  Base64 key;
- a private fixed-size SHA-1 implementation hashes exactly that 24-byte key
  followed by `258EAFA5-E914-47DA-95CA-C5AB0DC85B11`;
- a private fixed-size encoder maps the 20-byte digest to the canonical
  28-byte padded accept value.

These functions allocate no heap memory, accept no arbitrary algorithm or
alphabet, and are not re-exported. Tests cover RFC vectors, all frozen client
keys/accepts, zero/one/high-bit nonces, and one-bit mutations of key, GUID, hash
rounds, and Base64 padding. Adding a crypto/Base64 dependency, `unsafe`, a
build script, or a proc macro remains a gate failure.

## Configuration additions

`ConnectionLimits` and its private checked form add:

| limit | default | hard ceiling | relationship |
| --- | ---: | ---: | --- |
| handshake header count | 32 | 4,096 | count excludes status line and terminal empty line |
| handshake header-line bytes | 512 | 1,048,576 | includes CRLF and must not exceed handshake bytes |

The existing handshake-byte default is 4,096 and ceiling is 1,048,576. New
`LimitKind` variants are `HandshakeHeaderCount` and
`HandshakeHeaderLineBytes`. Zero, ceiling-plus-one, platform conversion, and
cross-field failures are rejected during `ConnectionConfig` construction.
The client request can still fail with `LimitExceeded` when a syntactically
valid descriptor does not fit a particular configuration.

No adapter-local handshake limit is permitted.

## Private incremental parser

Client state adds a private phase:

```text
AwaitingStart -> AwaitingResponse { expected_accept, descriptor, parser }
              -> Opened | Failed
```

The public lifecycle remains `Connecting`, `Open`, or `Closed`. The parser
retains at most `handshake_bytes`, consumes every transport chunk once, and
tracks total bytes, current line bytes, header count, and CRLF progress across
arbitrary chunk boundaries. A limit is checked before retaining the byte that
would exceed it. The complete header block is recognized only by exact
`\r\n\r\n`.

After completion, parsing works over offsets into the one bounded byte buffer;
it does not allocate attacker-controlled header maps or strings. Header names
are ASCII case-insensitive and must be RFC token bytes. Optional whitespace is
trimmed from values. Duplicate names are detected case-insensitively with a
bounded scan and every duplicate is rejected, including otherwise unknown
headers.

Validation order is stable:

1. role, client phase, and public lifecycle;
2. total, line, and header-count limits while consuming bytes;
3. exact CRLF framing and status-line grammar;
4. exact `HTTP/1.1` and three-digit status `101`;
5. unique headers and valid header-name tokens;
6. `Upgrade` contains the case-insensitive comma token `websocket`;
7. `Connection` contains the case-insensitive comma token `upgrade`;
8. exactly one `Sec-WebSocket-Accept`, byte-equal after OWS trimming to the
   stored RFC derivation;
9. absence of `Sec-WebSocket-Extensions` and
   `Sec-WebSocket-Protocol`;
10. zero bytes after the terminal CRLF in the same transport input.

Other response headers are accepted when syntactically valid and unique.
Upgrade and Connection may contain other valid comma members; substring
matches such as `not-an-upgrade` never count. A chunk ending before the header
terminator is ordinary incomplete progress, not a failure. EOF in that phase
is a typed partial-handshake failure. If a chunk contains a valid response and
even one following byte, the whole step fails as trailing data before `Open`;
no frame or application byte is delivered.

## Typed failures

`HandshakeFailure` becomes a populated public vocabulary:

```rust
pub enum HandshakeFailure {
    WrongRole,
    ClientHandshakeAlreadyStarted,
    ResponseBeforeClientRequest,
    MalformedStatusLine,
    HttpVersionNot11,
    StatusNotSwitchingProtocols { received: u16 },
    BareLineEnding,
    ObsoleteLineFolding,
    MalformedHeader,
    InvalidHeaderName,
    DuplicateHeader,
    MissingUpgrade,
    InvalidUpgrade,
    MissingConnection,
    InvalidConnection,
    MissingAccept,
    AcceptMismatch,
    UnexpectedExtension,
    UnexpectedSubprotocol,
    UnexpectedEof,
    TrailingData { bytes: u64 },
}
```

Configured limits continue through `FailureKind::LimitExceeded`; descriptor
construction uses the separate `ClientRequestDescriptorError`. No failure
variant contains an attacker-controlled string, Java exception name, or text
that callers must parse.

Wrong role, a repeated start command, and request-before-response misuse emit
no output and preserve the current state. Once a client request was emitted,
every malformed/invalid response, limit failure, partial EOF, or trailing-data
failure is fatal: the core clears buffered handshake bytes, changes to
`Closed`, emits exactly one `StateChanged(Closed)`, and returns the typed
failure with `state_after: Closed`. Repeated input in `Closed` follows the
existing typed invalid-state contract and cannot duplicate the transition.

## Ordered step semantics

The exact outputs are:

| input/outcome | outputs in order | failure | final state |
| --- | --- | --- | --- |
| valid `StartClientHandshake` | `TransportWrite(canonical_request)` | none | `Connecting` |
| incomplete response chunk, including empty chunk | none | none | `Connecting` |
| complete valid response with no trailing byte | `StateChanged(Open)`, then `SemanticEvent(ClientHandshakeOpened { descriptor })` | none | `Open` |
| fatal response/EOF/limit failure after request | `StateChanged(Closed)` | exact typed failure | `Closed` |
| caller misuse before request | none | exact typed failure | unchanged |

The state is committed before the corresponding output is appended, matching
the invariant that consumers observing `ClientHandshakeOpened` already see
`Open`. `StepResult.state()` and `TypedProtocolFailure.state_after` always
equal the committed core state. No success result contains application data.

After `Open`, later transport input remains
`ProtocolSliceUnavailable { owner_story: FrameCoding }` until US-012. Server
role transport input remains owned by US-011. Local message, control, and close
commands remain owned by their existing stories.

## RED -> GREEN public seams

Implementation is test-first through the public interface:

1. **RED descriptor/start seam:** imports of `ClientRequestDescriptor` and the
   start command fail; GREEN validates descriptor injection defenses and emits
   exact request bytes for fixed nonces.
2. **RED accept derivation seam:** the RFC nonce/accept vector and frozen
   client-key vectors fail; GREEN supplies private fixed-size Base64/SHA-1.
3. **RED incremental seam:** a valid response split at every byte boundary
   fails; GREEN produces exactly one Open transition/event for every split.
4. **RED typed-rejection seam:** status, header, token, accept, duplicate,
   extension, subprotocol, EOF, trailing, and three limit families fail; GREEN
   produces the exact variant, one Closed transition, zero application data.
5. **RED evidence seam:** new production symbols remain unresolved and corpus
   links absent; GREEN binds exact rust-analyzer symbols, vector/property/fuzz
   receipts, compatibility/cutover obligation, ledger records, and DAG nodes.

Properties use deterministic fixed seeds without `rand`: all valid response
split points are equivalent; ASCII case permutations preserve required-header
meaning; token-list placement preserves meaning; any accept-bit mutation
rejects; any suffix rejects; and retained bytes never exceed config. Fuzz seed
files cover incomplete CRLF, oversized line/count/total, duplicate casing,
obs-fold, invalid token bytes, extension/subprotocol, and valid-response-plus-
frame-looking suffix. Normal debug and release tests replay every seed.

Runtime assertions remain internal and check phase/state consistency, retained
bytes at or below the checked cap, expected-accept presence exactly while
awaiting a response, and no semantic/application output before a successful
open. An assertion is not acceptance evidence by itself.

## Evidence and migration closure

The migration map must not create 17 Java-shaped Rust aliases. Rows touched by
US-010 are reconciled as capability replacements to the small real symbol set:

- `websocket_core::ConnectionCore`;
- `websocket_core::ClientRequestDescriptor`;
- `websocket_core::LocalCommand`;
- `websocket_core::HandshakeFailure`;
- `websocket_core::SemanticEvent`.

Only symbols present in the exact pinned offline rust-analyzer SCIP index may
set `rust_identity_verified:true`. The map schema/receipt evolves to allow an
additive US-010 resolution receipt while preserving the immutable US-009
three-symbol receipt. Unrelated later-story rows remain unresolved.

US-010 evidence must bind source commit/tree, pinned rustc/rust-analyzer
digests, exact test command/results, public vector digest, all-split property
counts, fuzz-seed inventory/results, runtime-assertion inventory, migration
resolutions, compatibility/cutover IDs, and delta record digests. The evidence
DAG adds a US-010 claim supported by those immutable nodes. It may claim only
client request generation and response validation under owner-attested
assurance; it cannot claim server handshake, frames, parity, conformance,
Autobahn, release, publication, or production readiness.

## Intended implementation paths

Production and tests:

- `rust/connection-core/src/lib.rs`
- `rust/connection-core/src/connection.rs`
- `rust/connection-core/src/handshake.rs`
- `rust/connection-core/src/handshake/client.rs` (new)
- `rust/connection-core/src/handshake/http.rs` (new, private reusable parser
  mechanics for US-011 without implementing server behavior)
- `rust/connection-core/src/handshake/crypto.rs` (new, private fixed-size
  transform)
- `rust/connection-core/tests/connection_contract.rs`
- `rust/connection-core/tests/client_handshake.rs` (new)
- `rust/connection-core/fuzz-seeds/us010/` (new public inert seeds)
- `rust/connection-core/Cargo.toml` (description only; dependencies stay empty)

Public corpus/evidence tooling and receipts:

- `corpora/handshake/client.json` (new US-010 projection/augmentation; the
  frozen 49-case corpus remains unchanged)
- `schemas/client-handshake-corpus-1.0.0.schema.json` (new)
- `internal/corpora/client_handshake.go` and its tests (new deterministic
  generator/validator; no shell logic)
- `evidence/us010-client-handshake.json` (new)
- `evidence/intake/semantic-id-migration-map.json`
- `schemas/semantic-id-migration-map-1.1.0.schema.json` or a compatible
  versioned successor
- `evidence/intake/compatibility-surface.json`
- `evidence/intake/cutover-contract.json`
- `evidence/java/behavior-delta-ledger.json`
- a versioned successor to
  `schemas/behavior-delta-ledger-1.0.0.schema.json`
- `assurance/evidence-dag.json`

The implementation worker may omit a listed path only if the same obligation
is already satisfied by an existing canonical artifact and records that
reconciliation. It must not modify `.file-locks.json`.

## Completion boundary

US-010 is complete only when the exact request and all response rules pass in
debug and release, every valid vector passes at every byte split, every
adversarial vector and fuzz seed returns its exact typed result, the full
workspace gates remain green with zero dependencies/unsafe/build hooks, and
all evidence/migration/cutover/delta links validate at the committed head.

Passing US-010 does not make the core a complete WebSocket implementation.
Server handshakes, frames, messages, control frames, close, driven concurrency,
TCP, Autobahn conformance, parity, benchmarking, and release remain owned by
later stories.
