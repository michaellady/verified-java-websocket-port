# US-018 thin blocking TCP adapter contract

## Claim boundary

US-018 adds one safe-Rust, standard-library-only loopback testee crate around
the exact US-017 owner. It proves the current macOS arm64 checkout can connect
or accept one TCP socket, preserve borrowed reads and partial-write progress,
translate bounded transport termination into the existing driver inputs, and
exit with a bounded typed report. All opening-handshake, frame, message,
fragmentation, control, close, limit, and lifecycle decisions remain in
`websocket_core::ConnectionCore` behind
`websocket_driver::ConnectionOwner::poll`.

The owner has relaxed the original story. This story may complete with
current-host `std::net` loopback and process evidence. It must not claim Linux
x86_64 or both-platform execution, live Java cross-peer behavior, Autobahn,
TLS, proxying, reconnection, an async runtime, extension or compression
support, a general production client/server interface, signing, publication,
production readiness, or independent review. Actual signal-driven EINTR
injection, application echo/control routing, and conformance-runner behavior
also remain later evidence; ordinary `ErrorKind::Interrupted` handling is
implemented and unit-exercised without claiming a native signal test.

Assurance is `OWNER_ATTESTED_NOT_INDEPENDENT` and
`independent_review_claimed` is `false`.

## Reconciled baseline

The architecture starts at
`6a7606ac0fc216e5c87148faf98c957ab18af324`. The shipped Rust workspace contains
`websocket-core` at `rust/connection-core` and `websocket-driver` at
`rust/websocket-driver`. The physical `crates/websocket-testee/...` paths in
the early PRD are stale; the adapter joins the incumbent workspace at
`rust/websocket-testee` rather than creating a second Rust root.

The exact promoted seams are:

- `websocket_driver::connection_driver(ConnectionConfig, Role)`;
- the returned sole `websocket_driver::ConnectionOwner`;
- `ConnectionOwner::poll(DriverInput) -> PollResult`; and
- its paired cloneable `CommandHandle`, used only to submit the explicit
  client `StartClientHandshake` command in this bounded story.

US-017 already owns command admission, command/inbound arbitration, ordered
outputs, retained write suffixes, flush notification, EOF/shutdown
convergence, and exactly-once terminal delivery. The TCP crate must consume
those behaviors, not wrap `ConnectionCore` directly or reconstruct them.
US-010 and US-011 already make the client descriptor/nonce and inbound server
request the only opening-handshake inputs. Socket address resolution,
connect/accept, read/write calls, and process exit are therefore the remaining
adapter concerns.

The current workspace is external-dependency-free and safe Rust. US-018 keeps
that property: the only new Cargo edges are local path edges from
`websocket-testee` to `websocket-driver` and `websocket-core`; there is no
registry, git, build, dev, target-specific, or proc-macro dependency. This
design was produced independently and borrows no Claude implementation.

## Problem and seam

Deleting the TCP module should force every testee to rediscover only transport
mechanics: how to retry interrupted calls, preserve a deferred read, report an
exact partial write, bound time and memory, map EOF versus lost transport,
drain one owner to terminal, and normalize process results. Deleting it must
not make protocol parsing or state-machine logic reappear, because that logic
already belongs to the deeper core and owner modules.

The new deep module is the private connected-socket pump. Two narrow
role-specific entry points acquire the socket and immediately delegate to it:

```rust
pub fn run_client_once(fixture: ClientFixture) -> AdapterReport;

pub fn run_server_once(
    listener: std::net::TcpListener,
    fixture: ServerFixture,
) -> AdapterReport;
```

`ClientFixture` contains a loopback `SocketAddr`, checked
`ConnectionConfig`, validated `ClientRequestDescriptor`, explicit `[u8; 16]`
nonce, and checked `IoBounds`. `ServerFixture` contains checked
`ConnectionConfig` and `IoBounds`. It accepts no application callback,
transport trait, protocol parser, codec, clock implementation, allocator,
extension point, or ambient randomness source. The pre-bound listener lets a
test reserve port zero and discover the exact address without a readiness
callback; `run_server_once` still owns the sole accept and the accepted socket.
Both roles reject non-loopback local or peer addresses before entering the
driver.

The implementation-only seam is:

```rust
fn drive_connected(
    stream: std::net::TcpStream,
    handle: websocket_driver::CommandHandle,
    owner: websocket_driver::ConnectionOwner,
    bounds: IoBounds,
) -> AdapterReport;
```

The client entry point validates the fixture, performs one bounded connect,
constructs `connection_driver(config, Role::Client)`, and submits exactly one
`LocalCommand::StartClientHandshake { descriptor, nonce }` before entering
the pump. The server entry point validates the pre-bound loopback listener,
performs one bounded accept, verifies the peer is loopback, constructs
`connection_driver(config, Role::Server)`, and enters the same pump. There is
one owner and one command handle per connected socket and no reconnect or
multi-connection loop.

`AdapterReport` is the sole result interface. It contains the role, normalized
socket/setup outcome, normalized termination cause, bounded ordered driver
observations, read/write call and byte counters, partial-progress counters,
timeout/interruption counters, owner-turn count, and the final driver state.
It does not retain raw peer input, duplicate complete transport writes, expose
a live socket, or claim that a setup failure before owner construction reached
a core terminal state. Tests and the binary consume this same report rather
than inspecting pump internals.

## Design it twice

### Rejected design A: generic transport port and router callbacks

One design introduced `BlockingTransport`, `Clock`, and `ReportSink` traits
and a callback invoked for each semantic event. It would make artificial
partial-I/O tests easy, but only one real adapter exists, so those seams are
hypothetical. The interface would require callers to understand readiness,
callback reentrancy, error translation, cancellation, and ownership of
borrowed writes. It also risks moving application/conformance behavior into
US-018. The extra flexibility is shallow and explicitly outside the relaxed
story.

### Rejected design B: independent client and server loops

A second design placed complete read/write loops in `client.rs` and
`server.rs`. Its public role entry points were simple, but the implementation
duplicated deferred-input retention, write-progress accounting, timeout
mapping, terminal draining, report bounds, and retry policy. Fixing one peer
loss or partial-write defect would not fix the other role, so it failed the
locality test.

### Chosen design: two acquisition adapters, one connected pump

The chosen design keeps role-specific acquisition and the client start command
at two tiny adapters, then centralizes every transport rule in one private
`drive_connected` module. The public interface has two entry points because
connect and accept genuinely vary; no trait is introduced because there are
not two transport implementations. The interface is the test surface: public
loopback tests drive the same functions as the executable, while focused
module tests exercise only deterministic error classification and bound
validation.

This has depth as leverage: one pump covers both roles and hides every partial
I/O, retry, buffer, timeout, shutdown, reporting, and termination rule. It has
locality: a transport-accounting defect is fixed once. The seam remains clean:
the pump knows driver inputs and outputs but no WebSocket grammar.

## Checked bounds and resource ownership

`IoBounds::try_new` validates values before bind/connect/accept, buffer
allocation, or process work:

| Bound | Required behavior |
| --- | --- |
| `read_buffer_bytes` | nonzero, no greater than the core's checked `total_buffered_bytes`, allocated once |
| `max_write_chunk_bytes` | nonzero, no greater than `total_buffered_bytes`; caps each socket write request so partial driver progress is deterministic |
| `connect_timeout` | nonzero and at most 30 seconds |
| `accept_timeout` | nonzero and at most 30 seconds |
| `read_timeout` | nonzero and at most 30 seconds |
| `write_timeout` | nonzero and at most 30 seconds |
| `max_owner_turns` | at least 4,105 and at most 1,000,000; includes one work turn plus a reserved worst-case terminal drain |
| `max_report_entries` | nonzero and no greater than 4,096 |

The pump allocates one fixed read buffer and never copies a driver write into a
second buffer. A successfully read prefix remains in that buffer until the
owner reports it consumed. The pump performs no next read while the same bytes
are deferred. Report entries are admitted before append; exhausting the report
or ordinary turn slice records one bounded failure, supplies one `Shutdown`,
and drains without further growth inside the configured total
`max_owner_turns`. The reserved drain slice covers the exact core's checked
4,096-entry event queue, the fixture's sole client-start command, and fixed
terminal transitions; Shutdown discards queued writes synchronously. Counters
use checked arithmetic; overflow has a typed adapter outcome and follows the
same shutdown path.

The listener handles one connection only. The accepted `TcpStream`, driver
owner, command handle, fixed read buffer, and report belong to one stack. No
global, thread-local, background worker, callback, mutex, channel, task, or
socket registry is added. Loopback integration tests may put the opposite peer
on a native `std::thread`, but production adapter code starts no thread.

`max_write_chunk_bytes` is a fixture control, not protocol framing: the pump
passes only a prefix of the exact `DriverOutput::Write` slice to
`TcpStream::write` and reports the returned byte count unchanged. The driver,
not the adapter, retains the remaining suffix and decides when a complete
transport write is flushed.

## Connected pump algorithm

The pump is a single blocking state loop with one pending input buffer and one
absolute deadline per socket operation:

1. Drain the current `PollResult` before reading again. Ordered events, state
   changes, failures, command dispositions, and terminal outcomes are appended
   to the bounded report exactly as observed.
2. For `DriverOutput::Write(bytes)`, call `write` with at most
   `max_write_chunk_bytes`. `Ok(n > 0)` becomes exactly
   `DriverInput::WriteProgress { bytes: n }`. `Ok(0)` is normalized as lost
   write service and becomes `Shutdown`; it is never reported as progress.
3. For any non-write output, call `poll(Wake)` only after recording that
   output. For `Idle`, first retry retained inbound bytes; otherwise perform
   one bounded blocking read.
4. `read` `Ok(n > 0)` creates `TransportBytes::new(&buffer[..n])` and supplies
   `DriverInput::Inbound`. `Consumed { bytes: n }` releases the buffer.
   `Deferred` retains the identical bytes and offset. Any other consumed count
   is an adapter invariant failure; the adapter never splits one read behind
   the driver's back.
5. `read` `Ok(0)` supplies `TransportEof` exactly once. The pump then drains
   owner output without another read. A reset, broken pipe, write zero, or
   other loss of required transport service is recorded distinctly and
   supplies `Shutdown` exactly once.
6. `ErrorKind::Interrupted` retries the identical socket operation without
   polling the owner, advancing progress, changing the retained read, or
   resetting its absolute deadline. `WouldBlock` or `TimedOut` at the deadline
   records the operation and supplies `Shutdown`. The adapter invents no core
   timeout command because the exact US-017 interface has none.
7. `Shutdown` discards no owner accounting. The pump continues bounded
   `poll(Wake)` calls until the one driver `Terminal`, or reports
   `OwnerTurnLimit` if the contract is violated. After terminal it calls
   `TcpStream::shutdown(Both)` once and returns. Later socket errors cannot
   create a second terminal observation.

`run_server_once` uses the standard library's lack of an accept timeout
explicitly: it temporarily sets only the listener nonblocking, retries
`WouldBlock` against one absolute `Instant` deadline with a fixed bounded
backoff, restores blocking mode on the accepted stream, and then uses the
shared blocking pump. This is a synchronous standard-library fixture, not an
async or readiness abstraction. `Interrupted` retries against the same accept
deadline.

Failures before a driver exists (`InvalidBounds`, `NonLoopback`, `Bind`,
`Connect`, `Accept`) return a bounded setup report. Failures after driver
construction (`ReadTimeout`, `WriteTimeout`, `ReadIo`, `WriteIo`,
`PeerServiceLost`, `ReportLimit`, `CounterOverflow`, `OwnerTurnLimit`) name the
transport cause separately from the final driver state. A report may state
that adapter shutdown was initiated; it must not relabel a timeout or reset as
a clean peer WebSocket close.

## Process fixture

`src/main.rs` is a small testee router over the same two public functions. It
accepts exactly `client` or `server`, a numeric loopback socket address, and
the role-specific bounded fixture fields. The client additionally accepts a
request target, Host value, and exact 32-hex-digit nonce. It performs no DNS,
configuration-file, environment-secret, stdin protocol, daemon, reconnect, or
multi-client behavior.

The executable prints one deterministic summary line derived from
`AdapterReport`; it never prints raw inbound bytes or credentials. Stable exit
classes are `0` for a delivered driver terminal, `2` for usage/configuration,
`3` for bind/connect/accept setup failure, `4` for bounded transport timeout or
peer-service loss, and `5` for an adapter invariant/resource failure. The
server handles one accepted connection and exits. Signal handling and graceful
daemon lifecycle are not claimed.

## Linkage and architecture gate

`rustgate` is extended by role, not weakened globally:

- `connection-core` retains its existing ambient-`std` prohibition;
- `websocket-driver` retains its exact collections/atomics/Arc/mpsc
  allowlist;
- only `websocket-testee` production roots may import the exact standard
  library modules needed for `io`, `net`, `time`, synchronous backoff,
  argument routing, formatting, and process exit;
- the new crate must have exactly
  `websocket-driver = { path = "../websocket-driver" }` and
  `websocket-core = { path = "../connection-core" }`, with no other
  dependency entry; and
- production adapter sources must contain the promoted
  `connection_driver`/`ConnectionOwner::poll` path and must not construct or
  name `ConnectionCore`, `CoreInput`, `CoreOutput`, `FrameEncoder`,
  `FrameHeaderDecoder`, `OutboundFrame`, `Opcode`, masking helpers, close
  machines, handshake parsers, or a protocol callback.

The architecture scan also rejects adapter-production protocol parsing
canaries: WebSocket/HTTP wire literals and a byte-index plus opcode-bitmask
branch are forbidden outside Rust test fixtures. A Go hostile-fixture test
injects an adapter-side function equivalent to
`bytes[0] & 0x0f` plus an opcode branch and must receive the typed
`ADAPTER_PROTOCOL_BRANCH` finding. Separate mutants remove the driver
constructor/poll linkage and replace either local path dependency; they must
receive `ADAPTER_LINKAGE_MISSING` or the existing dependency finding. These are
architecture canaries, not a formal proof that arbitrary Rust cannot obscure
a parser.

Rust integration tests may contain fixed RFC wire vectors for the opposite
loopback peer. `rustgate` scans the adapter's production roots for protocol
branches and only requires `#![forbid(unsafe_code)]` on test roots, so a test
fixture does not force a protocol literal into the adapter implementation.

## RED -> GREEN -> REFACTOR plan

All REDs are committed as genuine failures before implementation:

1. **Public seam RED.** Add compile-time integration tests importing
   `run_client_once`, `run_server_once`, `ClientFixture`, `ServerFixture`,
   `IoBounds`, and `AdapterReport`. The focused Cargo target must fail because
   the workspace member and interface do not exist.
2. **Linkage RED.** Add rustgate good/hostile fixture expectations for the new
   workspace member, two exact local dependency edges, required constructor
   and owner-poll use, and the adapter-protocol-branch seed. The Go tests must
   fail because rustgate neither permits the role nor emits the required typed
   finding.
3. **Server loopback RED.** A pre-bound port-zero listener receives a canonical
   request split across one-byte peer writes. `read_buffer_bytes = 1` and
   `max_write_chunk_bytes = 3` must prove exact inbound retention, multiple
   write-progress reports, a core-produced 101, server-open observations, EOF,
   and one terminal report through `run_server_once`.
4. **Client loopback RED.** A mock loopback server reads the exact core-produced
   request and returns the valid response in bounded chunks. The client uses
   an explicit descriptor and nonce, records multiple read/write calls, feeds
   EOF once, and returns one terminal report through `run_client_once`.
5. **Transport-failure RED.** Current-host sockets cover failed connect,
   accept deadline, stalled read, bounded write/backpressure timeout, clean
   EOF, lost peer service, and explicit adapter shutdown. Each run has a fixed
   deadline and reconciles setup cause, driver terminal count, byte counters,
   and final state. Native reset/write failure assertions accept only the
   documented `std::io::ErrorKind` family rather than one unstable OS errno.
6. **Retry/bound RED.** Focused deterministic tests drive the private
   error-classification helper with `Interrupted`, `TimedOut`, and
   `WouldBlock`, proving Interrupted preserves the operation/deadline while
   timeout shuts down. Boundary and plus-one cases cover every `IoBounds`
   field, report capacity, checked counters, retained-read identity, and owner
   turn exhaustion. No native signal-injection claim is made.
7. **Process RED.** `CARGO_BIN_EXE_websocket-testee` tests verify invalid CLI,
   non-loopback rejection, failed connect, one successful server fixture, one
   successful client fixture, deterministic summary output, exit classes, and
   bounded child termination. Tests use Rust process control, not a shell
   wrapper.

GREEN requires all focused tests plus the complete locked/offline Rust debug
and release suites, Clippy, rustfmt, Cargo metadata, rustgate Go tests, full Go
tests, vet, build, port-plan verification, and all predecessor formal/frame
replays. REFACTOR may consolidate only private report/accounting helpers; it
must not add another public method, transport trait, callback, dependency, or
protocol branch.

## Evidence and nonclaims

`evidence/us018-blocking-adapters.json` binds the architecture, exact source
tree, workspace graph, driver/core link symbols, host/toolchain, test counts,
loopback/process matrices, deadlines, partial-progress counts, normalized
failures, architecture mutants, and all nonclaims. It records actual observed
values rather than copying this design's planned counts. Any predecessor
receipt whose Cargo, policy, rustgate, or source binding changes is refreshed
without changing its historical runtime claim.

Completion proves only a bounded current-host standard-library TCP fixture
drives the exact shipped owner and core without an adapter-side protocol
branch. It does not prove cross-platform socket behavior, conformance, Java
parity, exhaustive failure behavior, race freedom, production suitability, or
release authority.

## Implementation file and lock plan

The implementation worker needs the following exact paths:

- `rust/Cargo.toml`
- `rust/Cargo.lock`
- `rust/websocket-testee/Cargo.toml`
- `rust/websocket-testee/src/lib.rs`
- `rust/websocket-testee/src/client.rs`
- `rust/websocket-testee/src/server.rs`
- `rust/websocket-testee/src/io_loop.rs`
- `rust/websocket-testee/src/main.rs`
- `rust/websocket-testee/tests/loopback.rs`
- `rust/websocket-testee/tests/process.rs`
- `internal/rustgate/verify.go`
- `cmd/rustgate/main_test.go`
- `rust/dependency-policy.toml`
- `rust/dependency-inventory.toml`
- `security/rust-dependency-unsafe-inventory.json`
- `evidence/us018-blocking-adapters.json`

The architecture file remains locked until its commit is recorded. Evidence
refresh may additionally require locks for `evidence/us010-client-handshake.json`
through `evidence/us017-driver.json` after the implementation commit is fixed.
It must not edit unrelated US-006, US-007, or US-017 concurrency-plan locks.
