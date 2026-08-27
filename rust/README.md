# Rust workspace (enabling scaffold)

Pinned, gated, safe-Rust workspace for the verified Java -> Rust WebSocket
port. This directory is **enabling work only**: it exists so US-009
("Establish the safe Rust ConnectionCore contract") can start instantly when
its dependencies unblock. **No user story is claimed complete by anything in
this directory**, and no performance representation of any kind is made --
compile/test correctness only.

Full context: [`../docs/rust-workspace.md`](../docs/rust-workspace.md).

## Layout

- `rust-toolchain.toml` -- pins the intake-qualified toolchain, `1.95.0`
  (see `evidence/intake/toolchain-pins.json`).
- `ws-core/` -- UNIMPLEMENTED placeholder for the Sans-I/O
  `ConnectionCore` (US-009); library namespace `ws_core`, the canonical
  namespace fixed by the owner crate-naming decision (the migration map's
  `ws_core::` semantic ids are authoritative). Doc-only modules for
  handshake, framing, control, close, and the connection state machine;
  zero dependencies; `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
- `Makefile` -- the PRD quality-gate commands, verbatim.

## Gates

From this directory (or `make -C rust gates` from the repo root):

```sh
make fmt-check      # cargo fmt --all -- --check
make clippy         # cargo clippy --workspace --all-targets --all-features -- -D warnings
make test           # cargo test --workspace --all-targets --all-features
make test-release   # cargo test --workspace --release
make gates          # all of the above
```

## Policies

- `#![forbid(unsafe_code)]` on every first-party crate; a smoke test parses
  `src/lib.rs` and fails if the attribute is removed.
- Dependency-free Sans-I/O core by design; a smoke test fails if a dependency
  table gains an entry. Any future dependency requires enumerated-unsafe
  review per the PRD quality gates.
- `Cargo.lock` is committed for reproducibility.
