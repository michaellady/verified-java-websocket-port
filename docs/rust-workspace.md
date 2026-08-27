# Rust workspace: scope, gates, and story mapping

Status: **US-009 core contract and US-010 client opening handshake shipped.**
The `rust/` workspace now contains the dependency-free Sans-I/O
`ConnectionCore` and its first protocol-bearing slice. Rust implementation may
continue before the benchmark confirmation host binds, but no performance
representation is authorized beyond compile/test correctness.

**Explicit non-claims:**

- US-009 claims only the safe bounded core contract and US-010 claims only
  client request generation plus server-upgrade response validation.
- Server opening handshakes, frames, messages, control behavior, close,
  adapters, and driven concurrency remain unavailable until their owning
  stories.
- No performance representation of any kind is made. No benchmark sample was
  collected, no tuning performed.
- Autobahn, live Java differential execution, fresh US-010 rust-analyzer
  resolution, publication, production, parity, and independent review are not
  claimed.

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
| US-011 | `src/handshake.rs` -- server opening handshake. |
| US-012 | `src/framing.rs` -- canonical framing, masking, allocation limits. |
| US-013 | `src/framing.rs` -- strict text/binary message delivery. |
| US-014 | `src/framing.rs` -- bounded fragmentation reassembly. |
| US-015 | `src/control.rs` -- ping/pong control behavior. |
| US-016 | `src/close.rs` -- close, EOF, terminal states. |
| US-017 | `src/connection.rs` -- single-owner bounded command boundary. |
| US-018 | future sibling crate(s) for thin blocking TCP adapters (not scaffolded; adapters are deliberately outside the dependency-free core). |
| US-019 | future Autobahn conformance harness wiring against the adapters (not scaffolded). |

## Current shipped state

- The crate remains `rust/connection-core` with package/library identities
  `websocket-core` / `websocket_core`.
- The workspace is dependency-free, forbids first-party unsafe code and build
  hooks, and is gated through the pinned Rust toolchain.
- US-010 evidence lives in `evidence/us010-client-handshake.json` and binds
  exact checkout blob IDs, content digests, corpus/fuzz inputs, and the
  additive evidence DAG. The cutover obligation remains `DECLARED`.
