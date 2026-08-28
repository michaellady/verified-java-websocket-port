# Rust workspace: scope, gates, and story mapping

Status: **US-009 through US-018 are shipped; US-019 provides inert conformance
readiness; US-020 adds the bounded neutral differential process seam; US-024
ships the owner-relaxed private output-lifecycle refinement; US-025 ships only
the owner-relaxed resource-decision mechanics outside the Rust crates.** The
`rust/` workspace contains the dependency-free Sans-I/O `ConnectionCore`, the
single-owner driver, and the thin blocking and one-record neutral adapters.
US-024 centralizes the driver's pending-output and partial-write state in a
private `OutputLedger` without changing public declarations or the core
contract. US-025 retains absent raw ledgers, unbound hosts, and
`INCONCLUSIVE_BLOCKED` measurement acceptance. No performance representation
is authorized beyond compile/test correctness.

**Explicit non-claims:**

- US-020 extends protocol behavior only with outbound fragmented sends. Exact
  consumption/buffer accounting and frame traces are read-only observations
  at the existing decoder/encoder seams.
- `websocket-testee neutral-oracle --protocol NDRV1` is a strict, bounded,
  dependency-free process codec over `ConnectionOwner`; it is not another
  WebSocket parser or state machine.
- No performance representation of any kind is made. No benchmark sample was
  collected, no tuning performed.
- No fresh Autobahn run, Linux run, publication, production, parity, or
  independent-review claim is made by this workspace. The process seam alone
  is not a passing Java-versus-Rust differential receipt.

## Toolchain pin

`rust/rust-toolchain.toml` pins channel `1.95.0`, matching the
digest-qualified intake pin in `evidence/intake/toolchain-pins.json`
(`rustc-1.95.0-aarch64-apple-darwin`). A unit test inside `connection-core`
fails if the pin drifts from `1.95.0`. Edition 2024, `rust-version = 1.95.0`.

## Quality gates

`rust/Makefile` carries the PRD qualityGates commands verbatim; the root
Makefile is untouched (wiring rust gates into the root build belongs to the
pipeline stories, not this scaffold):

| Target | Command |
| --- | --- |
| `fmt-check` | `cargo fmt --all -- --check` |
| `clippy` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| `test` | `cargo test --workspace --all-targets --all-features` |
| `test-release` | `cargo test --workspace --release` |

## Safety and dependency policy

- Every first-party crate carries `#![forbid(unsafe_code)]` (PRD gate) and
  `#![deny(missing_docs)]` so the eventual public contract arrives
  documented. A smoke test (`connection-core/tests/scaffold_smoke.rs`) parses
  the library source and fails if either attribute is removed.
- **Design stance: the Sans-I/O core is dependency-free.** It transforms
  bytes and commands into typed values without sockets, clocks, or
  callbacks, so it needs nothing beyond `std`. A smoke test fails if any
  dependency table gains an entry; adding one is a deliberate, reviewed
  change that also triggers the PRD's enumerated-dependency-unsafe review.
- `Cargo.lock` is committed (currently trivial -- no external crates) to keep
  the reproducible-lockfile gate honest from day one.

## How the workspace maps to stories

| Story | Workspace surface and state |
| --- | --- |
| US-009 | **Complete.** `connection-core` owns the checked config, role, command/write/event/state/failure vocabulary, single mutating `ConnectionCore::step` seam, and workspace gates. |
| US-010 | **Complete.** `src/handshake/client.rs`, `http.rs`, and `crypto.rs` implement the client opening handshake through `ConnectionCore::step`; later protocol slices still fail closed. |
| US-011 | **Complete.** `src/handshake/server.rs` strictly validates bounded incremental requests and emits only the canonical 101 plus the parser-produced descriptor event. |
| US-012 | **Complete.** Canonical frame coding, masking, and allocation limits. |
| US-013 | **Complete.** Strict text/binary message delivery and outbound final frames. |
| US-014 | **Complete.** Bounded inbound fragmentation reassembly. |
| US-015 | **Complete.** Bounded ping/pong observation and explicit control writes. |
| US-016 | **Complete.** Close, EOF, and terminal-state behavior. |
| US-017 | **Complete.** `websocket-driver` owns the bounded producer queue and sole mutable `ConnectionOwner`. |
| US-018 | **Complete on the current host.** `websocket-testee` provides thin bounded blocking loopback client/server adapters. |
| US-019 | **Inert readiness only.** `harness-contract` records `READY_NO_LIVE_CONFORMANCE`; it does not execute Autobahn. |
| US-020 | **Rust process seam implemented.** `SendFragment`, exact read-only step accounting/frame traces, real Open/Closing/Closed bootstraps, and strict one-record `NDRV1`/`NOBS1` transport. A separate differential run and receipt determine story completion. |
| US-024 | **Owner-relaxed refinement mechanics complete.** `ConnectionOwner` delegates its private ordered-output, partial-write, flush, and undrainable-write lifecycle to `output::OutputLedger`. The 74-scenario before/after replay is equal; the original parity, protected, formal, independent, performance, and release blockers remain. |
| US-025 | **Owner-relaxed resource-decision mechanics complete outside the Rust crates.** The exact 12-workload/120-endpoint matrix is sample-free and `INCONCLUSIVE_BLOCKED`; no host binding, raw ledger, measurement, performance, or independent-recompute claim exists. |

## Current shipped state

- The workspace has three first-party packages: `websocket-core`,
  `websocket-driver`, and `websocket-testee`. The only dependency edges are
  local workspace edges; there are no external crates.
- `websocket-driver::output::OutputLedger` is private. It does not add a public
  type, dependency, allocator, lock, thread, socket, callback, clock, unsafe
  block, or second state machine.
- All three packages forbid first-party unsafe code and build hooks and are
  gated through the pinned Rust toolchain.
- US-010 and US-011 evidence lives in the two story receipts under `evidence/`.
  They bind exact checkout blob IDs, content digests, frozen corpus rows,
  deterministic nonce/accept literals, fuzz inputs, and additive story DAGs.
  Both cutover obligations remain `DECLARED`.
