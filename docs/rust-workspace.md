# Rust workspace: scope, gates, and story mapping

Status: **enabling scaffold only.** The `rust/` workspace was created so
US-009 ("Establish the safe Rust ConnectionCore contract") can begin the
moment its open dependencies (US-005, US-006, US-008) unblock, per the
owner-authorized implementation-ordering amendment (Rust implementation work
may begin before the benchmark confirmation host binds, provided it makes no
performance representations beyond compile/test correctness).

**Explicit non-claims:**

- No user story (US-009 or any other) is claimed complete, started-toward
  acceptance, or partially accepted by this scaffold.
- No WebSocket behavior exists: every module in `connection-core` is an
  empty, documented placeholder marked UNIMPLEMENTED.
- No performance representation of any kind is made. No benchmark sample was
  collected, no tuning performed.
- US-009's own first acceptance criterion (separately authorized repository
  handoff, sbx-executed builds, scaffold canaries, audit/lockfile gates) is
  **not** satisfied here; this scaffold does not substitute for it.

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

| Story | Workspace surface (future home; nothing implemented) |
| --- | --- |
| US-009 | `connection-core` crate: the `ConnectionCore` contract types in `src/connection.rs` (config/role/commands/writes/events/state/failures), plus workspace gates. US-009 may rename or relocate crates (its PRD `files` list sketches a root-level `crates/websocket-core`); this scaffold does not pre-commit that decision. |
| US-010 | `src/handshake.rs` -- client opening handshake. |
| US-011 | `src/handshake.rs` -- server opening handshake. |
| US-012 | `src/framing.rs` -- canonical framing, masking, allocation limits. |
| US-013 | `src/framing.rs` -- strict text/binary message delivery. |
| US-014 | `src/framing.rs` -- bounded fragmentation reassembly. |
| US-015 | `src/control.rs` -- ping/pong control behavior. |
| US-016 | `src/close.rs` -- close, EOF, terminal states. |
| US-017 | `src/connection.rs` -- single-owner bounded command boundary. |
| US-018 | future sibling crate(s) for thin blocking TCP adapters (not scaffolded; adapters are deliberately outside the dependency-free core). |
| US-019 | future Autobahn conformance harness wiring against the adapters (not scaffolded). |

## What this scaffold changed

- `rust/` (new): workspace `Cargo.toml` + `Cargo.lock`, `rust-toolchain.toml`,
  `Makefile`, `README.md`, `connection-core` crate with doc-only modules and
  smoke tests.
- `.gitignore`: appended explicit `rust/` target-directory entries.
- `docs/rust-workspace.md` (this file).

Nothing under `evidence/`, `internal/`, `cmd/`, `schemas/`, `terraform/`,
`.github/`, `java-oracle/`, `benchmarks/`, the root `Makefile`, or
`.dialed.yml` was touched, and the Go module builds and tests unchanged.
