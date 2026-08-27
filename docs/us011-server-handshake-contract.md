# US-011 server opening-handshake contract

Status: implementation-ready architecture for the server opening-handshake
slice. This design is bounded to US-011. It adds request validation and the
successful 101 response through the existing Sans-I/O core; frame and
application-data behavior remains unavailable until US-012 and later stories.

Assurance remains `OWNER_ATTESTED_NOT_INDEPENDENT` with
`independent_review_claimed:false`. This story authorizes no Autobahn rerun,
live Java execution, publication, production mutation, socket, clock,
randomness source, dependency, `unsafe`, `build.rs`, proc macro, or generic
HTTP-server behavior.

## Baseline and reconciled paths

The implementation starts from `websocket_core` at
`7c76e1ac731a1f27663028883d03698cd6b81e46`. The physical crate is
`rust/connection-core`; its package and library identities remain
`websocket-core` and `websocket_core`. Early `ws_core` and
`crates/websocket-core` planning names are stale. US-011 updates generated
planning identities to the real crate instead of creating compatibility
modules for names that never shipped.

US-009 owns the only mutating seam,
`ConnectionCore::step(CoreInput) -> StepResult`. US-010 supplies checked
handshake limits, deterministic output ordering, private bounded HTTP-head
mechanics, fixed-size SHA-1/Base64 encoding, and fatal handshake closure. The
server slice deepens those modules. It does not add a parser object, handshake
builder, callback, listener, socket, or response-builder API.

The frozen handshake corpus contains 39 `client_request` cases owned by this
story: six accepts, 29 rejects, and four incomplete prefixes. Their exact IDs
are `us005.hs.0000` through `0005`, `0009` through `0034`, and `0042` through
`0048`. The corpus itself is immutable. A US-011 projection binds those rows
and additive adversarial vectors without changing their RFC verdicts.

Relevant existing obligations are:

- `corpora/handshake/cases.jsonl` and its committed manifest;
- the independent Go RFC evaluator in `internal/corpora/handshake.go`;
- the source-derived Java mapping in
  `evidence/us005-handshake-live-mapping.json`;
- `surface.handshake.server-response` and
  `cutover.surface-handshake-server-response`;
- `slice.server-handshake` and its eleven dossier seams;
- `property.handshake.key-accept-roundtrip` and
  `property.handshake.server-response-total`;
- `EXCLUDED_EXTENSION_SUBPROTOCOL_PARITY` and
  `EXCLUDED_RFC_7692_PERMESSAGE_DEFLATE`.

## Authority and deliberate Java deltas

Decisions keep the established priority:

1. RFC 6455 plus directly applicable HTTP grammar and message-framing rules;
2. the independent Go RFC evaluator and frozen public vectors;
3. Java-WebSocket v1.6.0 source-derived differential observations.

Java remains useful differential evidence, not permission to lower the RFC.
The Java server accepts several inputs this slice must reject: missing Host,
Upgrade, or Connection; malformed/noncanonical Base64 keys; decoded keys of
the wrong length; certain duplicate or invalid-name headers; bare-LF folding;
and over-limit heads. Java also parses method/version spellings more
permissively and buffers the handshake without the Rust bounds. Those known
differences remain explicit in the existing mapping.

No committed-corpus Java case is newly executed in US-011. The story verifies
all 39 cases against the existing source-derived Java observable model and
records the mode as `SOURCE_DERIVED_NO_LIVE_COMMITTED_CORPUS_EXECUTION`.
Without a new governed runtime observation, the behavior-delta ledger remains
unchanged: no fabricated record and no unrelated Autobahn reference. The
evidence receipt records `NO_REGISTERED_CATEGORY_0_AT_PIN` and zero Autobahn
executions.

## One public seam and two public values

Transport input already carries every byte needed by a server. No start
command is added. The only new public data type is an immutable descriptor
created by successful parsing, and the only new event reports that accepted
descriptor:

```rust
pub struct ServerRequestDescriptor { /* private owned fields */ }

impl ServerRequestDescriptor {
    pub fn request_target(&self) -> &str;
    pub fn host(&self) -> &str;
}

pub enum SemanticEvent {
    ClientHandshakeOpened { /* existing */ },
    ServerHandshakeOpened {
        descriptor: ServerRequestDescriptor,
    },
}
```

`ServerRequestDescriptor` deliberately has no public constructor: it is proof
that the server core accepted the request through `step`. It owns the raw,
validated origin-form request target and Host value. The request target begins
with `/`, contains visible ASCII only, and contains no fragment marker `#`;
query text and percent-encoded octets remain undecoded. Host is nonempty
visible ASCII with no whitespace, comma, control, DEL, or line injection. DNS,
URI routing, TLS authority selection, percent decoding, and application
authorization are adapter/application concerns.

The client and server descriptors remain different public types because their
construction proves different facts. Their private field validation may share
one helper. US-011 does not rename or widen `ClientRequestDescriptor`.

No public request headers, header map, key, nonce, SHA-1 object, Base64 codec,
parser, extension list, subprotocol list, or HTTP status builder is added.

## Private server state

`ConnectionCore` adds one private `ServerHandshake` alongside the existing
client handshake:

```text
AwaitingRequest { parser } -> Opened | Failed
```

The public lifecycle remains `Connecting`, `Open`, or `Closed`. For a
server-role core in `Connecting`, each `CoreInput::Transport` is consumed by
that parser. An empty chunk is ordinary incomplete progress. EOF while still
awaiting a complete head is fatal `UnexpectedEof`.

After success, server-role transport input is owned by US-012 and returns
`ProtocolSliceUnavailable { owner_story: FrameCoding }`; it is never routed
back to the handshake parser. Client-role behavior from US-010 is unchanged.
A server receiving `StartClientHandshake` continues to return `WrongRole`
without state or output changes.

## Shared bounded HTTP-head mechanics

`handshake/http.rs` is refactored privately into a direction-neutral bounded
head accumulator plus request- and response-specific validation. The shared
piece owns only mechanics already common to both directions:

- exact CRLF recognition across arbitrary chunk boundaries;
- total-byte, current-line, and header-count accounting before retention;
- terminal `\r\n\r\n` recognition;
- case-insensitive header-name comparison;
- HTTP token, field-value-octet, OWS, and comma-token helpers;
- duplicate-name detection without an attacker-sized header map;
- trailing-byte detection.

It must preserve every US-010 client verdict, limit attempt, output, and split
behavior byte-for-byte. Request-line grammar and request-field requirements
belong only to the new server validator; status-line and accept validation
remain only in the client validator.

The accumulator retains at most `handshake_bytes`. A byte that would exceed a
limit is never retained. Parsing after completion uses offsets into that one
bounded buffer and bounded scans; it does not allocate attacker-controlled
header strings or collections. Unknown, syntactically valid, unique headers
are ignored unless they create HTTP message framing as described below.

## Exact request grammar and validation order

The request line is exactly:

```text
GET {origin-form-target} HTTP/1.1\r\n
```

Method matching is case-sensitive. There is exactly one SP at each separator,
exactly three components, no leading/trailing SP, and no HTAB separator. The
version is the exact uppercase literal `HTTP/1.1`. The target uses the
descriptor rules above. Absolute-form, authority-form, asterisk-form, empty,
fragment-bearing, whitespace-bearing, control-bearing, and non-ASCII targets
reject.

Header names are valid HTTP tokens and are compared case-insensitively. Header
values accept only HTAB, SP, visible ASCII, and obs-text at the syntactic
layer. A line beginning with SP or HTAB is obsolete folding and rejects.
Every duplicate field name rejects, including otherwise unknown fields.

Validation order is stable:

1. public lifecycle, role, and private phase;
2. total, line, and field-count limits while bytes arrive;
3. exact CRLF framing and complete-head boundary;
4. no byte after the terminal CRLF in the completing input;
5. exact request-line structure, `GET`, target, and `HTTP/1.1`;
6. header name/value syntax, obsolete folding, and duplicates;
7. absence of `Content-Length` and `Transfer-Encoding`;
8. exactly one valid Host;
9. Upgrade contains the case-insensitive comma token `websocket`;
10. Connection contains the case-insensitive comma token `upgrade`;
11. Sec-WebSocket-Version is exactly `13` after OWS trimming;
12. Sec-WebSocket-Key is canonical standard Base64 for exactly 16 bytes;
13. absence of Sec-WebSocket-Extensions and Sec-WebSocket-Protocol;
14. canonical response capacity against the same checked limits.

Upgrade and Connection may contain other syntactically valid comma members;
empty members or substring matches never count. Required scalar fields do not
accept comma joining. `Content-Length` and `Transfer-Encoding` reject even
when empty or apparently harmless: this slice never accepts an HTTP request
body, and passing either through would create intermediary-dependent framing.

Trailing bytes in the completing input reject the entire step. They are not
interpreted as a frame and no 101 is emitted. This is the explicit request-
smuggling boundary until US-012 owns frame bytes on a later step.

## Canonical key validation and response

The private crypto module adds a fixed-shape standard-Base64 decoder for the
request key. A valid key is exactly 24 ASCII bytes, uses the standard alphabet,
ends with exactly `==`, has canonical zero pad bits, decodes to exactly 16
bytes, and re-encodes byte-for-byte to the received value after outer OWS is
trimmed. URL-safe alphabet, embedded whitespace, alternate padding,
noncanonical pad bits, invalid alphabet, and any other decoded length reject.

The accepted 24-byte key is passed to the existing private RFC accept
derivation. No ambient randomness is involved. For the RFC key
`dGhlIHNhbXBsZSBub25jZQ==`, the accept value remains
`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`.

The only successful response is exactly:

```text
HTTP/1.1 101 Switching Protocols\r\n
Upgrade: websocket\r\n
Connection: Upgrade\r\n
Sec-WebSocket-Accept: {derived-28-byte-value}\r\n
\r\n
```

Spelling, reason phrase, header order, single SP after each colon, and CRLF are
fixed. There is no Date, Server, content framing, extension, subprotocol, or
application-selected header. Total length, four nonempty lines, three header
fields, and each line length are computed with fallible arithmetic and checked
before allocation. A response-capacity failure is fatal before `Open` and
emits no partial write.

## Typed failure additions

The existing `HandshakeFailure` vocabulary is extended, not replaced:

```rust
pub enum HandshakeFailure {
    // existing client/shared variants
    MalformedRequestLine,
    MethodNotGet,
    InvalidRequestTarget,
    MissingHost,
    InvalidHost,
    MissingKey,
    InvalidKeyEncoding,
    InvalidKeyLength { decoded: u64 },
    MissingVersion,
    UnsupportedVersion,
    UnexpectedContentLength,
    UnexpectedTransferEncoding,
    // existing UnexpectedExtension, UnexpectedSubprotocol,
    // UnexpectedEof, TrailingData, and shared HTTP variants
}
```

Shared failures remain `HttpVersionNot11`, `BareLineEnding`,
`ObsoleteLineFolding`, `MalformedHeader`, `InvalidHeaderName`,
`InvalidHeaderValueOctet`, `DuplicateHeader`, `MissingUpgrade`,
`InvalidUpgrade`, `MissingConnection`, and `InvalidConnection`. Configured
limits remain `FailureKind::LimitExceeded` with exact kind, attempted, and
maximum values. No failure stores an attacker-controlled string or asks a
caller to parse text.

Every syntactic, semantic, smuggling, limit, response-capacity, and EOF failure
after server parsing begins is fatal: clear retained handshake bytes, set the
private phase to `Failed`, commit `Closed`, emit exactly one
`StateChanged(Closed)`, and return the typed failure with
`state_after: Closed`. Later input follows the existing `InvalidState`
contract and cannot duplicate the transition.

## Ordered step results

The exact observable results are:

| input/outcome | outputs in order | failure | final state |
| --- | --- | --- | --- |
| empty or incomplete valid request prefix | none | none | `Connecting` |
| complete valid request, no suffix | `TransportWrite(101)`, `StateChanged(Open)`, `SemanticEvent(ServerHandshakeOpened { descriptor })` | none | `Open` |
| malformed/invalid/smuggled/over-limit request | `StateChanged(Closed)` | exact typed failure | `Closed` |
| EOF before completion | `StateChanged(Closed)` | `UnexpectedEof` | `Closed` |
| transport after successful Open | none | `ProtocolSliceUnavailable { FrameCoding }` | `Open` |

The core commits `Open` before constructing the returned `StepResult`, while
output order instructs adapters to write the 101 before publishing the state
and semantic event. A consumer observing `ServerHandshakeOpened` therefore
sees `Open`, and an ordered output consumer cannot publish Open before the
response write. No result contains application data.

## TDD seams and exact vector plan

The pre-agreed test seam is only public behavior through
`ConnectionCore::step`; getters on the parser-produced descriptor are the
read-only value seam. Tests never call private HTTP or crypto functions.
Implementation proceeds as vertical RED -> GREEN -> REFACTOR slices:

1. one RFC request fails to compile/accept; add server state, descriptor,
   canonical 101, ordered outputs, and the RFC key/accept literal;
2. frozen requests fail; add exact request-line and required-field validation;
3. arbitrary splits fail; add bounded incremental accumulation;
4. adversarial typed cases fail; add duplicates, controls, excluded headers,
   smuggling, EOF, and three limit families;
5. evidence checks fail; add projection, fuzz inventory, exact source/test
   bindings, migration reconciliation, and the US-011 evidence DAG.

The independent projection includes all 39 frozen client-request rows. Each
of the six accepted requests runs at every two-chunk split point, including
empty first/last chunks: 1,092 exact executions per profile. Each accepted
request also runs byte-at-a-time and under three committed deterministic
multi-chunk plans, adding six and 18 executions per profile. Incomplete frozen
prefixes remain nonfailing until explicit EOF, which then yields
`UnexpectedEof`.

Additive literals cover lowercase method, extra request-line tokens,
absolute/asterisk/fragment targets, Host grammar, required-token placement,
version spellings such as `+13` and `0013`, standard/Base64 boundary cases,
canonical pad-bit mutations, controls and DEL in each line category,
case-insensitive duplicates, content framing, excluded negotiation, exact
limits, and response-capacity failure.

Committed inert fuzz seeds under `fuzz-seeds/us011/` cover exactly these 17
classes: bare LF, obsolete folding, invalid header name, forbidden value
control, malformed request line, duplicate casing, Content-Length,
Transfer-Encoding, noncanonical key, wrong decoded key length, extension,
subprotocol, incomplete CRLF, valid request plus suffix, total limit, line
limit, and count limit. Debug and release tests replay every seed through
`step` and assert its exact typed result.

Deterministic properties, with no `rand`, are:

- all two-way split points and byte-at-a-time delivery match the unsplit
  response bytes, descriptor, output order, and final state;
- ASCII case permutations of field names and required token members preserve
  the accepted meaning, while method and HTTP-version case mutations reject;
- each of 256 deterministic 16-byte nonce vectors encoded canonically
  produces the literal accept computed by the independent Go evaluator;
- any Base64 alphabet, padding, pad-bit, decoded-length, or interior-space
  mutation rejects before Open;
- adding any suffix, body-framing field, extension, or subprotocol rejects and
  emits neither 101 nor semantic event;
- retained bytes never exceed the checked cap and a fatal input emits exactly
  one Closed transition.

Internal runtime assertions check server phase/lifecycle consistency, retained
bytes within the cap, no 101/event on a failure path, exact response allocation
length, and Open committed before the success outputs. Assertions support
debugging; they are not acceptance evidence by themselves.

The required Rust back pressure is `make -C rust gates`, which includes debug
and release tests, Clippy, formatting, metadata, dependency, unsafe, and build-
hook checks. The independent Go validators run with `go test -count=1 ./...`
under the already pinned JDK path. No test is skipped or loosened.

## Evidence, migration, and cutover closure

The US-011 projection and evidence receipt bind:

- the immutable 39-case source digest and exact selected IDs/verdicts/configs;
- additive vector and 17-seed digests plus exact expected typed results;
- exact debug/release commands and real passed/failed counts;
- the 1,092 two-chunk, six bytewise, and 18 multi-chunk executions per profile;
- source checkout blob IDs and SHA-256 values for every implementation,
  executable test, and verifier file through the hardened bounded artifact
  reader established by US-010;
- pinned rustc/cargo identities and the historical US-009 rust-analyzer
  receipt, without treating the local rustup proxy as the pinned resolver;
- compatibility surface, dossier slice, cutover obligation, Java mapping,
  migration rows, unchanged delta ledger, and story-specific DAG digests;
- owner-only assurance and all nonclaims in this document.

Artifact paths are exact allowlisted repository-relative paths. The verifier
rejects absolute paths, `..`, backslashes, root escapes, symlinks,
non-regular/multilink files, size over 16 MiB, and before/open/after identity
changes. For every path, it resolves the exact checkout `HEAD` entry, verifies
that the object is a blob with the receipt's byte size and blob ID, and binds
the receipt's SHA-256 to the same bytes read from the working tree through a
bounded, repository-root-pinned, no-follow handle. This requires only `HEAD`
and its checkout, works in a depth-1 clone, and never depends on a parent or
historical commit. US-011 reuses or extracts that incumbent reader; it does not
create a weaker second reader.

Migration rows owned by `slice.server-handshake` reconcile Java-shaped stale
targets to the small shipped capability set:

- `websocket_core::ConnectionCore`;
- `websocket_core::ServerRequestDescriptor`;
- `websocket_core::HandshakeFailure`;
- `websocket_core::SemanticEvent`.

No `ServerHandshake`, `ServerHandshakeBuilder`, `HandshakeImpl1Server`,
`ws_core`, or `crates/websocket-core` compatibility alias is fabricated.
Only `ConnectionCore` remains resolver-verified by the immutable US-009 SCIP
receipt. New US-011 symbols are source-bound and explicitly resolver-
unverified unless the exact pinned resolver becomes available and is actually
run.

`cutover.surface-handshake-server-response` remains `DECLARED`; US-011 does
not promote it merely because source and tests exist. The receipt links its
own evidence to the obligation, while the canonical cutover evidence list
stays empty until the separately governed promotion occurs.
`assurance/us011-evidence-dag.json` may claim only server request validation,
canonical 101 generation, and normalized Open event behavior. It cannot claim
frames, application data, complete WebSocket conformance, Java parity,
Autobahn, independent review, release, publication, production, or benchmark
readiness.

## Anticipated implementation paths

Production and executable tests:

- `rust/connection-core/src/lib.rs`
- `rust/connection-core/src/connection.rs`
- `rust/connection-core/src/handshake.rs`
- `rust/connection-core/src/handshake/http.rs`
- `rust/connection-core/src/handshake/crypto.rs`
- `rust/connection-core/src/handshake/server.rs` (new)
- `rust/connection-core/tests/server_handshake.rs` (new)
- `rust/connection-core/tests/connection_contract.rs`
- `rust/connection-core/fuzz-seeds/us011/` (new inert seeds)
- `rust/connection-core/Cargo.toml` (description only; dependencies empty)

Projection, validation, and evidence:

- `corpora/handshake/server.json` (new projection; frozen JSONL unchanged)
- `schemas/server-handshake-corpus-1.0.0.schema.json` (new)
- `schemas/server-handshake-evidence-1.0.0.schema.json` (new)
- `internal/corpora/server_handshake.go` and tests (new)
- the incumbent hardened artifact reader, generalized without weaker checks
- `internal/corpora/schemas.go`
- `evidence/us011-server-handshake.json` (new)
- `assurance/us011-evidence-dag.json` (new)
- `evidence/intake/semantic-id-migration-map.json`
- `evidence/intake/compatibility-surface.json`
- `evidence/intake/port-seam-dossier.json`
- `internal/portplan/slices.go`, `build_documents.go`, validation, and
  targeted tests
- `docs/rust-workspace.md`

The behavior-delta ledger and cutover contract are verified as unchanged
unless implementation discovers a real governed observation or schema repair;
they are not edited to manufacture completion. The frozen handshake corpus is
never edited.

Four retained US-006 locks exist:
`assurance/formal/proof-targets.json`,
`assurance/formal/backend-qualification.json`,
`assurance/formal/connection-model.tla`, and
`assurance/concurrency/plan.json`. US-011 requires none of them and must not
modify them. Its story-specific DAG avoids the prior formal-fixture collision.
`.file-locks.json` is never committed or modified by an implementation worker.

## Completion boundary

US-011 is complete only when all 39 frozen request vectors and additive
adversarial cases return exact typed results, all six valid requests pass the
declared arbitrary-chunk executions in debug and release, canonical 101 bytes
and output ordering are literal, limits and smuggling fail before Open, all
workspace and Go gates are green, and every evidence/migration reference
validates at the committed head under owner-only assurance.

Passing US-011 does not make the core a complete WebSocket implementation.
Frames, messages, fragmentation, ping/pong, close/EOF protocol behavior,
driven concurrency, TCP, Autobahn conformance, parity, benchmarking, release,
publication, and production remain owned by later work.
