# US-009 ConnectionCore contract

Status: execution-ready architecture for an interface/infrastructure story.
It defines no opening-handshake, frame, message, fragmentation, control, close,
TCP, or Autobahn behavior and makes no parity, conformance, performance,
production, or release claim.

Assurance is `OWNER_ATTESTED_NOT_INDEPENDENT` and
`independent_review_claimed` is `false`.

## Provenance and resolved inputs

This design borrows analysis from Claude's 780-line
`workspace/orchestrator/verified-java-websocket-port-claude/drafts/us009-connectioncore-contract-draft.md`.
That draft is reference material, not an independent first finish. This design
keeps its useful Sans-I/O, bounded-allocation, and single-owner ideas, but does
not adopt its Java-first fidelity policy or its proposed `ws_core` identity.

The repository handoff required before story writes is satisfied:

| Fact | Reconciled value |
| --- | --- |
| bound repository | `repos/public/verified-java-websocket-port` with a Git common directory distinct from the HQ root repository |
| remote | `git@github.com:michaellady/verified-java-websocket-port.git` / `https://github.com/michaellady/verified-java-websocket-port` |
| owner/name | `michaellady/verified-java-websocket-port` |
| default branch | `main` (`origin/HEAD -> origin/main`) |
| license | Apache-2.0; `LICENSE` is `sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` |
| authorization | immutable receipt `companies/enterprise-vibe-code/projects/verified-java-websocket-port/research/repository-authorization.json`, repository node `R_kgDOUCmfcQ` |
| manifest/registry | laboratory `lab-java-websocket` and registry entry `lab-java-websocket` agree on URL, owner, public visibility, Apache-2.0, `main`, protection, release rule, and initial commit |

The historical authorization receipt and registry retain their original
Open Source Projects labels. The owner-authorized company-move record permits
those immutable bytes to remain while current planning and external authority
route through Enterprise Vibe Code. No cross-company credential transfer is
inferred.

## Architectural decision

`websocket_core::ConnectionCore` is the one deep, dependency-free, safe-Rust
module at the protocol seam. Its small interface owns input admission,
resource accounting, lifecycle state, ordered output, and typed failures.
Networking/runtime adapters, corpus adapters, proof harnesses, and the Java
oracle may translate at their own outer seams, but none may own or copy
protocol state.

The physical crate remains `rust/connection-core` to avoid a gratuitous move.
The implementation phase renames its package to `websocket-core` and its
library target to `websocket_core`. This preserves the exact US-006 future
production targets:

- `websocket_core::frame::mask::apply_mask_in_place`
- `websocket_core::frame::decode::FrameHeaderDecoder::decode_header`

It also preserves the separate US-017 owner target
`websocket_driver::owner::ConnectionOwner::step`. The semantic-ID migration
map's planned `ws_core::...` names are resolver-unverified proposals, not
facts. US-009 must amend those rows to the actual `websocket_core` identities
and obtain rust-analyzer resolution receipts; it must not add Java-shaped
aliases merely to make a stale planned name resolve.

## Public interface

The crate root re-exports only the caller vocabulary. Implementation modules
remain private unless a later proof target explicitly requires a narrower
`pub` item.

```rust
pub struct ConnectionCore { /* one mutable owner; no interior mutability */ }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role { Client, Server }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState { Connecting, Open, Closing, Closed }
pub struct TransportBytes<'a> { /* borrowed bytes; construction does not copy */ }
pub enum LocalCommand {
    SendText(Box<str>),
    SendBinary(Box<[u8]>),
    SendPing(Box<[u8]>),
    SendPong(Box<[u8]>),
    Close { code: u16, reason: Box<str> },
}
pub enum CoreInput<'a> { Transport(TransportBytes<'a>), Command(LocalCommand), TransportEof }
pub struct TransportWrite { /* owned wire bytes */ }
pub enum SemanticEvent { /* stable typed vocabulary, populated by US-010..016 */ }
pub enum CoreOutput { TransportWrite(TransportWrite), SemanticEvent(SemanticEvent), StateChanged(ConnectionState) }
pub struct StepResult { /* opaque bounded sequence in exact occurrence order */ }
impl StepResult {
    pub fn outputs(&self) -> impl ExactSizeIterator<Item = &CoreOutput>;
    pub fn failure(&self) -> Option<&TypedProtocolFailure>;
    pub fn state(&self) -> ConnectionState;
}
impl ConnectionCore {
    pub fn new(config: ConnectionConfig, role: Role) -> Self;
    pub fn step(&mut self, input: CoreInput<'_>) -> StepResult;
    pub fn state(&self) -> ConnectionState;
}
```

`step` is the only mutating core operation. It opens no socket, reads no
clock, starts no thread, invokes no callback, and consults no ambient global.
Given the same validated config, role, current state, and ordered inputs, it
returns the same typed sequence byte-for-byte. `StepResult` is one unified
sequence so adapters cannot accidentally reorder writes, events, and state
changes by draining separate collections.

US-009 implements admission, bounds, ordering, initial state, and failure
plumbing only. Until their owning stories land, protocol-bearing inputs must
produce the explicit `ProtocolSliceUnavailable` failure and no successful
wire or semantic output. The corpus no-stub canary must therefore reject a
US-009-only candidate. A deterministic failure is not a handshake or frame
implementation.

## Immutable configuration and limits

`ConnectionConfig` has private fields, is constructed by
`ConnectionConfig::try_from(ConnectionLimits)`, and is immutable after
construction. External values enter as `u64`; every value is checked for zero,
hard ceiling, cross-field consistency, and fallible conversion to `usize`
before any capacity is allocated.

| Limit | Default | Hard ceiling |
| --- | ---: | ---: |
| handshake bytes | 4,096 | 1,048,576 |
| frame bytes | 1,048,576 | 1,048,576 |
| message bytes | 1,048,576 | 1,048,576 |
| total buffered bytes | 1,048,576 | 1,048,576 |
| event queue entries | 64 | 4,096 |
| command queue entries | 64 | 4,096 |
| write queue entries | 64 | 4,096 |

Every limit is nonzero. Frame and message limits must not exceed the total
buffered-byte limit. Aggregate capacity arithmetic is checked. The US-006
systematic-test capacities of two are exploration bounds, not production
defaults and not permission to silently clamp this config.

Limit checks occur before the guarded allocation or copy. Queues are bounded;
full means typed backpressure, never growth. Later protocol stories may add a
new limit only by extending this validated config and its full boundary table,
not by keeping an adapter-local limit.

## Typed failures

Failures are data, never panics, strings parsed by callers, or Java exception
names:

```rust
pub struct TypedProtocolFailure {
    pub kind: FailureKind,
    pub state_after: ConnectionState,
}
pub enum FailureKind {
    ProtocolSliceUnavailable { owner_story: ProtocolStory },
    Handshake(HandshakeFailure),
    Frame(FrameFailure),
    Utf8(Utf8Failure),
    Close(CloseFailure),
    LimitExceeded { limit: LimitKind, attempted: u64, maximum: u64 },
    Backpressure(QueueKind),
    InvalidState { input: InputKind, state: ConnectionState },
}
```

The nested protocol enums are reserved vocabulary in US-009; US-010..016 add
their actual production decisions and tests. Config construction has a
separate `ConfigError` because no connection exists yet. A fatal protocol
failure has one documented state effect, retained in `state_after`; no adapter
may reinterpret it.

## Ownership and concurrency seam

`ConnectionCore` is `Send` when its fields permit, but it is not internally
shared. Exactly one owner calls `step`. The only producer concurrency seam is
a dependency-free bounded MPSC command channel outside the core:

```rust
pub fn command_channel(capacity: CommandQueueCapacity)
    -> (CommandSender, CommandReceiver);
impl CommandSender {
    pub fn try_send(&self, command: LocalCommand)
        -> Result<(), CommandSendError>; // Full or ReceiverDropped
}
impl CommandReceiver {
    pub fn try_recv(&mut self) -> Result<LocalCommand, CommandReceiveError>;
}
```

Senders may be cloned; the receiver and core remain owned together by the
future `ConnectionOwner`. No blocking send or lock exposes protocol state.
FIFO holds within each producer; cross-producer order is the receiver's
observed order and becomes the owner's committed output order. Every accepted
command is applied once or receives one typed terminal disposition. Queue full
preserves accepted work and reports backpressure.

This interface is aligned with the nine US-006 actions and fixed properties.
Loom results remain `SYSTEMATIC_CONCURRENCY_TESTING`; they cannot become proof
or native-thread evidence. Production linkage remains future until the exact
owner symbol and all required call paths are resolver/receipt bound.

## Oracle policy

Behavior decisions follow the laboratory's frozen priority, in order:

1. RFC 6455 and directly applicable higher normative RFCs;
2. Autobahn 25.10.1 for the in-scope behavior it tests;
3. the independent neutral corpus;
4. Java-WebSocket v1.6.0 observation;
5. Rust candidate observation.

The Claude draft's Java-quirk catalogue is useful differential input, not a
contract. A Java quirk is mirrored only when higher authorities permit it and
an explicit `BehaviorDeltaLedger` decision says to do so. If Java and Rust
agree against a higher oracle, both are wrong. If they disagree, preserve the
input and classify the result; unresolved means blocked. Resource boundedness,
strict role masking, and safe single ownership are deliberate non-Java design
constraints already fixed by the manifest and US-006.

## Verification and promotion plan

Implementation proceeds test-first through this interface:

1. Rename package/library identities and reconcile the semantic map; retain
   the US-006 proof symbols exactly.
2. Add config tests for each limit at zero, one, default, boundary,
   boundary-plus-one, `u64::MAX`, conversion failure, and invalid cross-field
   relationships. Assert no guarded allocation occurs before rejection.
3. Add two-core determinism tests over identical configs and ordered
   byte/command inputs; compare the complete `StepResult` sequence and final
   state.
4. Add queue tests for exact capacity, FIFO per producer, full, receiver drop,
   accepted-work preservation, and owner-committed total order.
5. Add source/gate canaries proving first-party `unsafe`, socket/clock/thread/
   callback use, a dependency, an unbounded queue, and a fake protocol success
   all fail.
6. Prove the US-009-only candidate fails protocol corpus acceptance; do not
   execute or claim handshake/frame parity.

Under the owner's recorded relaxation, dependency-free first-party host
development, review, formatting, Clippy, and tests are permitted. Hostile or
dependency-bearing workloads and final promoted evidence remain gated by the
accepted US-007 Docker sbx profile. Sbx is a pre-promotion gate, not a design
blocker. No sbx, Autobahn, benchmark, network, production, signing, or
publication action is part of US-009 architecture.

## Completion boundary

US-009 can claim only the validated config, safe dependency-free workspace
gates, interface types, deterministic admission/output ordering, typed failure
plumbing, and bounded MPSC contract. `Handshake`, `Frame`, `Message`,
`Fragmentation`, `Control`, and `Close` remain visibly unavailable and owned by
US-010..016; driven concurrency belongs to US-017; TCP belongs to US-018. No
story, reviewer, or adapter may promote this contract into protocol parity.
