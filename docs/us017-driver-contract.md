# US-017 single-owner connection-driver contract

## Claim boundary

US-017 adds one safe-Rust, dependency-free driver module around the existing
Sans-I/O `websocket_core::ConnectionCore`. It serializes bounded commands,
transport facts, ordered protocol outputs, partial-write progress, shutdown,
and terminal delivery without sharing the mutable core. It does not add a
socket, callback, clock, timer, executor, background task, or ambient runtime.

The owner has relaxed the original evidence requirement so this story may
complete with deterministic bounded schedule exploration and a separately
recorded native `std::thread` stress run on the current host. That evidence is
systematic testing and stress testing, not proof or a race-detector result. This
story must not claim both blocking platforms, Loom, Miri, TSAN, a formal proof,
Autobahn, live-Java differential behavior, adapter conformance, production,
publication, or independent review unless those things are genuinely run and
recorded later.

## Problem and seam

`ConnectionCore::step` already owns all protocol mutation. US-017 must not put
a lock around it or reproduce its state machine in a concurrent wrapper. The
new deep module is `websocket_driver::ConnectionOwner`; its interface is the
only driver seam used by callers, tests, and later TCP/conformance adapters.
Deleting it would force every adapter to reimplement command admission,
arbitration, output ordering, partial-write retention, flush notification,
shutdown convergence, queue closure, and terminal suppression. That is the
complexity the module earns the right to hide.

Exactly one `ConnectionOwner` contains:

- one `ConnectionCore`;
- the private receiving half of one bounded command queue;
- one exact-order ledger of undelivered `CoreOutput` values;
- the cursor into the front pending transport write;
- the `TransportWriteFlushed`-due latch;
- inbound-versus-command arbitration state;
- shutdown/EOF latches; and
- the terminal-delivered latch and command-disposition counters.

The cloneable producer handle shares only the bounded queue and its closed bit.
It never contains or reaches the core. No other value can mutate protocol,
pending-output, write-progress, or terminal state.

## Design it twice

### Rejected design A: exposed parts

One plausible interface returned `(CommandSender, CommandReceiver,
ConnectionCore)` and let adapters own an event queue and write queue. It was
flexible, but shallow: callers had to know when to receive, when a core step was
safe, how many outputs it could retain, how partial writes affected later core
steps, when `TransportWriteFlushed` was truthful, and how to close the receiver
without losing an accepted command. The scheduling invariant would be copied
into every adapter and test, destroying locality.

### Rejected design B: spawned actor

Another plausible interface was `spawn(config, transport, callback) -> Handle`
with the implementation owning a thread or async task. It made the default case
short, but moved sockets, callbacks, scheduling, cancellation, clocks, and a
runtime choice into the interface. Tests would need runtime control or private
hooks, and US-018 could no longer supply both blocking adapters at the same
Sans-I/O seam.

### Chosen design: pull-driven owner

The chosen interface returns a cloneable bounded `CommandHandle` and one
pull-driven `ConnectionOwner`. Producers have one enqueue operation. The
adapter/test has one owner operation, `poll`, whose typed input covers wake,
inbound bytes, write progress, EOF, and adapter shutdown. `poll` returns input
disposition, at most one command disposition, the next ordered output, and the
current connection state. This has more depth and locality: all concurrency
and delivery policy is fixed once, while transports remain small adapters that
only retry deferred input, write the offered prefix, report progress, and drain
typed outputs.

Illustrative public shape (names and semantics are frozen; field visibility may
be expressed with constructors/getters):

```rust
pub fn connection_driver(
    config: ConnectionConfig,
    role: Role,
) -> (CommandHandle, ConnectionOwner);

impl CommandHandle {
    pub fn try_enqueue(
        &self,
        command: LocalCommand,
    ) -> Result<(), EnqueueError>;
}

impl ConnectionOwner {
    pub fn poll<'owner>(
        &'owner mut self,
        input: DriverInput<'_>,
    ) -> PollResult<'owner>;
}

pub enum DriverInput<'a> {
    Wake,
    Inbound(TransportBytes<'a>),
    WriteProgress { bytes: usize },
    TransportEof,
    Shutdown,
}

pub struct PollResult<'owner> {
    pub input: InputDisposition,
    pub command: Option<CommandDisposition>,
    pub output: DriverOutput<'owner>,
    pub state: ConnectionState,
}

pub enum DriverOutput<'owner> {
    Idle,
    Write(&'owner [u8]),
    Event(SemanticEvent),
    StateChanged(ConnectionState),
    Failure(TypedProtocolFailure),
    Terminal(TerminalOutcome),
}
```

`DriverOutput::StateChanged(Closed)` is forbidden. The first core transition to
`Closed` is normalized into exactly one `Terminal`; all later closed facts are
absorbed. A returned owned event is delivered. A returned `Write` is only an
offer and remains owned by the driver until acknowledged by `WriteProgress`.
The borrow prevents another mutable poll while the offered slice is live.

## Required outbound core evolution

The current core cannot honestly satisfy the producer-command criterion:
`SendText` and `SendBinary` still return `ProtocolSliceUnavailable`, and their
commands have no client mask key. US-017 therefore closes the explicit outbound
deferral left by US-013 before adding the driver:

```rust
LocalCommand::SendText {
    payload: Box<str>,
    mask_key: Option<[u8; 4]>,
}
LocalCommand::SendBinary {
    payload: Box<[u8]>,
    mask_key: Option<[u8; 4]>,
}
```

`ConnectionCore`, not the driver, uses the existing `FrameEncoder` to emit one
canonical final Text or Binary frame. Client role requires `Some(mask_key)`;
server role forbids a key. Keys are explicit, fresh caller inputs; neither
module generates, caches, or reuses entropy. Commands are accepted only in
`Open`. Payload, frame, total-buffer, and write-output admission is checked
before the core commits state or an output allocation. Failures are typed and
nonterminal unless the existing core contract says otherwise. The driver does
not call `FrameEncoder`, inspect opcodes, mask bytes, or own any protocol
encoding rule.

Focused core tests must establish exact server and client Text/Binary wire
bytes, role/key rejection, empty and boundary payloads, boundary-plus-one
rejection before guarded allocation, and unchanged state/output on rejection.

## Command queue and receiver ownership

The public `websocket_core::command_channel`, `CommandSender`, and
`CommandReceiver` were a US-009 staging seam. US-017 moves that behavior into
`websocket-driver`, renames the producer to `CommandHandle`, and makes the
receiver private. The core no longer exports a receiver that lets callers
separate it from the owner.

The implementation is a bounded safe-Rust MPSC queue with an atomic
close-and-drain operation. A small private `CommandReceiver` is held only by
the owner. Queue synchronization is shared transport/accounting state, never
shared protocol state. Producer enqueue does not wait for capacity:

- `Full(command)` returns ownership when the exact entry capacity is reached;
- `Contended(command)` returns ownership if the nonblocking queue lock is busy;
- `ReceiverDropped(command)` returns ownership after owner drop or terminal
  queue closure; and
- `LimitExceeded { command, attempted, maximum }` returns ownership before the
  command is retained when its logical retained bytes exceed its configured
  command class budget.

Queue closure and draining occur under the same private lock as enqueue. Thus a
producer cannot receive `Ok(())` after closure, and every command that did
receive `Ok(())` is either applied once by the owner or returned once as a
typed terminal rejection. Owner `Drop` marks the receiver dropped; it need not
deliver dispositions because no owner remains, but all future enqueues observe
`ReceiverDropped`. Dropping all handles does not close the protocol; the owner
observes `ProducersDropped` once and may continue processing transport input.

FIFO is guaranteed for successful calls through one handle. Clones racing with
one another have the single total order committed under queue admission; the
owner preserves that order. There is no producer-admission fairness promise:
`Full` and `Contended` are ordinary explicit backpressure.

## Poll, ordering, and write flushing

Each `poll` performs at most one owner transition and returns at most the next
ordered output. The algorithm is fixed:

1. Latch `TransportEof` or `Shutdown` immediately and atomically close producer
   admission. These inputs are consumed even while an output is pending.
2. If an output is pending, do not feed inbound bytes or another command to the
   core. Return the front output. An inbound input is `Deferred(OutputPending)`
   with zero bytes consumed and must be retried byte-for-byte.
3. `WriteProgress { bytes: 0 }` is a valid zero-progress schedule action and
   leaves the same suffix pending. Progress greater than the offered suffix is
   `Rejected(InvalidWriteProgress)` with no mutation. Positive in-range progress
   advances only the front write; later writes can never bypass it.
4. Removing the last byte of the last write produced since the previous flush
   sets `flush_due`. Once all earlier ledger outputs are delivered, the owner
   feeds exactly one `CoreInput::TransportWriteFlushed` before any new command
   or inbound bytes. Partial progress is never reported to the core as a full
   flush.
5. At a quiescent seam, a latched EOF/shutdown has priority and feeds one
   `CoreInput::TransportEof`. Graceful application shutdown remains the typed
   `LocalCommand::Close`; `Shutdown` means the transport will provide no more
   service and therefore cannot promise a close write.
6. Otherwise the owner applies at most one queued command or one supplied
   inbound buffer. If both exist, a retained turn bit alternates them. If the
   command wins, inbound is `Deferred(CommandTurn)` and must be retried exactly.
7. The complete `StepResult` is committed atomically into the ordered ledger.
   No later core step occurs until that ledger and any resulting flush fact are
   drained. `CoreOutput` occurrence order is preserved across writes, events,
   state changes, and failures.

Core failure is returned after all earlier outputs from that same step. A
command disposition says `Applied` only when the core accepted the command; it
says `Rejected(TypedProtocolFailure)` otherwise. On the first terminal core
result, the owner closes admission, atomically drains every already accepted
command into FIFO terminal-rejection dispositions, and places those before the
single `Terminal`. Nothing is introduced after `Terminal`, and later polls are
stable `Idle` with `Closed` state.

Inbound buffers are borrowed and are either consumed in full by the one core
step or consumed zero bytes. The owner never retains an adapter buffer. EOF and
shutdown are idempotent latches. Peer close, local close, and simultaneous close
remain core behavior and are not special-cased in the driver.

## Fairness and schedule bounds

The executable systematic explorer retains the version-1 bounds already
preregistered in `assurance/concurrency/plan.json`: two producers with two
commands each; one owner, inbound, flush, event-drain, and shutdown actor; two
inbound actions; three write-progress actions; three output drains; command,
write, and event capacities of two; at most seven tasks, 100,000 schedules,
three preemptions, and 1,000,000 branches.

The concrete driver refines the historical `callback-delivery` action to
`event-drain`; no callback exists. Fixed weak fairness applies only when the
owner has work, when an offered write is writable, and when an output is
pending. Producer admission has no fairness. The alternating turn bit gives a
continuously retried inbound buffer and an already queued command each a turn
after at most one competing quiescent transition. Fairness does not excuse an
adapter that stops polling, stops retrying deferred input, or reports no write
progress forever.

Reaching a schedule or branch maximum is recorded as bounded/truncated, never
as exhaustive. Every failing run must retain a deterministic minimized action
schedule and replay to the same property and semantic digest twice.

## Driver resource accounting

The driver reuses the validated `ConnectionConfig`; it has no unvalidated
second limits object. Owner construction checks all driver upper-bound
arithmetic with `checked_add`/`checked_mul` before creating the queue:

- accepted command entries are at most `command_queue_entries`;
- each accepted command's logical retained bytes are measured before enqueue
  and capped by its existing handshake or total-buffer class limit;
- the pending ledger contains outputs from only one core step and never more
  than `write_queue_entries` writes or `event_queue_entries` semantic events;
- pending write bytes are the exact owned wire lengths and every prefix advance
  is subtracted once;
- pending event payloads retain the core's immutable shared values rather than
  copying them; and
- terminal rejections replace, rather than duplicate, drained queue envelopes.

The evidence records high-water entry counts and logical bytes separately for
commands, writes, and events. Logical accounting is not a heap-profiler claim;
caller allocations exist before enqueue, allocator overhead is excluded, and
shared immutable payloads are charged once per owner-held reference. Overflow,
counter underflow, an entry above capacity, or a core batch that cannot fit the
declared ledger limits fails closed before later work is admitted.

## Adapter recipe

A blocking, conformance, differential, or test adapter uses the same recipe:

1. call `connection_driver`, clone only `CommandHandle`, and keep
   `ConnectionOwner` on one task/thread;
2. call `poll(Wake)` to apply queued work and drain outputs;
3. pass read bytes as `Inbound` and retain/retry them when disposition is
   deferred;
4. write only the exact `Write` suffix offered, then report the actual byte
   count through `WriteProgress`, including zero progress;
5. route owned `Event`, state, failure, command disposition, and `Terminal`
   values outside the driver without invoking user code inside `poll`;
6. report read EOF as `TransportEof` and loss of adapter service as `Shutdown`;
   and
7. stop only after the one `Terminal` has been drained.

Adapters never call `ConnectionCore::step`, never own the receiver, never
encode a frame, never mutate driver state through a callback, and never infer a
flush from a successful partial write.

## TDD and executable regression matrix

Implementation is test-first through the public driver seam:

| Area | RED observation | Required GREEN behavior |
| --- | --- | --- |
| Outbound data prerequisite | Text/Binary command returns unavailable | exact final masked/unmasked wire through `ConnectionCore` with explicit key rules and cap-before-commit |
| Producer bounds | capacity-plus-one accepted | exact capacity, typed full/contended/limit/drop, ownership returned on rejection |
| Queue closure race | enqueue reports success after terminal drain | atomic close-and-drain; every accepted command applied or terminal-rejected once |
| Ownership | core or receiver reachable from handle | only owner mutates core and owns private receiver |
| FIFO | one-handle or committed cross-clone order changes | producer FIFO and owner-commit order preserved |
| Arbitration | continuous inbound or commands starve the other | deterministic alternating turn with explicit deferred input |
| Pending writes | later write or core step bypasses partial front write | exact prefix retention and no new core step until ledger/flush discipline permits |
| Flush | partial write closes connection or complete write never flushes | exactly one core flush fact after the last acknowledged byte |
| Close races | local/peer/simultaneous close duplicates terminal | one ordered terminal after accepted-command dispositions |
| EOF/shutdown | signal lost behind pending output | signal latched once, admission closed, convergence after ordered drain |
| Event drain | callback/reentrant mutation or post-terminal event | owned return outside poll; no callbacks and no post-terminal output |
| Accounting | high-water or byte counter exceeds a checked bound | exact entry/byte maxima, overflow/underflow fail closed |
| Schedule evidence | scheduler result depends on discovery order | fixed bounds, stable semantic digest, deterministic minimization/replay |
| Native stress | accepted payloads lost, reordered, duplicated, or hang | bounded current-host `std::thread` run terminates and reconciles every accepted command |

The six files under `fuzz-seeds/us017/` are executable schedule data, not inert
fixtures: `lock-sharing`, `lost-command`, `queue-bypass`, `write-reorder`,
`close-race`, and `duplicate-delivery`. A seed names its property, full bounded
action sequence, expected bad mutation, and expected counterexample. The
shipped concurrency test must discover every file, replay it through the public
`CommandHandle`/`ConnectionOwner` seam, prove the corresponding mutation is
killed, and fail on an unknown, duplicate, unexecuted, surviving, or
nondeterministic seed.

Native stress is a separate test/receipt. It clones handles across real
`std::thread` producers while one owner thread drives the same public interface.
It records current platform, Rust/tool digest, source tree, repeat count,
accepted/applied/rejected totals, time bound, and flake reconciliation. A host
stress pass is not a race-detector pass and cannot satisfy the absent second
blocking platform.

## Evidence contract

`evidence/us017-driver.json` binds the exact architecture, core/driver sources,
tests, executable seed tree, `assurance/concurrency/plan.json`, toolchain, and
source-tree digest. It records:

- `story_id: US-017`, `seam: websocket_driver::ConnectionOwner::poll`, and the
  exact start/final commits;
- core outbound Text/Binary test totals and driver test totals in debug and
  release profiles;
- explored schedules, branches, preemptions, truncation state, fairness list,
  per-property outcomes, minimized/replay digests, and all six killed seeds;
- queue and logical-byte high-water marks for commands, writes, and events;
- native current-host platform/tool/source/repeat/timeout/flake totals;
- explicit limitations for the second blocking platform and absent
  Loom/Miri/TSAN/formal/Autobahn/live-Java/adapter evidence;
- `assurance: OWNER_ATTESTED_NOT_INDEPENDENT`,
  `independent_review_claimed: false`, `production: false`, and
  `publication: false`.

The receipt fails closed on an unresolved source identity, surviving or inert
seed, mismatched replay, missing limitation, count mismatch, exceeded resource
bound, unsupported claim, or post-terminal output. Conformance/differential
linkage remains a US-018/US-020 claim; sharing the designed seam does not prove
that an adapter already uses it.

## Primitive Test

The driver belongs in code. **Atomicity** passes because concurrent enqueue,
queue close-and-drain, owner order, write cursors, and terminal delivery would
corrupt state if callers implemented them independently. **Bitter Lesson**
passes because a smarter model would not improve deterministic FIFO,
cap arithmetic, or byte-progress accounting. **ZFC** passes because the module
is pure protocol transport and scheduling, not judgment. Evidence promotion
and interpretation remain in the prompt/review layer.

## Completion boundary

US-017 completes when the outbound Text/Binary prerequisite and the public
driver interface are implemented test-first, all bounded debug/release gates
pass, deterministic schedules kill all six executable defects, the separate
current-host native stress record reconciles, and bounded review/QA/reality
find no blocking correctness or security issue. Completion under the owner's
relaxation must preserve every named limitation above; it cannot be promoted
to multi-platform race freedom, external conformance, formal proof, adapter
completion, or production readiness.
