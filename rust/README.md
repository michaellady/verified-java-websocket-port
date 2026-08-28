# Rust workspace

Pinned, gated, safe-Rust workspace for the verified Java -> Rust WebSocket
port. US-009 through US-018 are shipped, US-019 retains inert conformance
readiness, US-020 provides the bounded neutral process seam, and US-024 has
completed its owner-relaxed private output-lifecycle refinement. None of those
facts is a parity-`READY`, independent-review, performance, publication,
production, or cutover claim.

Full context: [`../docs/rust-workspace.md`](../docs/rust-workspace.md).
US-024's exact boundary is in
[`../docs/us024-refinement-contract.md`](../docs/us024-refinement-contract.md).

## Layout

- `rust-toolchain.toml` -- pins the intake-qualified toolchain, `1.95.0`
  (see `evidence/intake/toolchain-pins.json`).
- `connection-core/` -- dependency-free Sans-I/O protocol core for handshake,
  framing, messages, fragmentation, control, close, limits, and connection
  state.
- `websocket-driver/` -- bounded producer queue and sole mutable
  `ConnectionOwner`. Its private `OutputLedger` owns ordered pending output,
  partial-write progress, batch flush facts, and undrainable-write cleanup.
- `websocket-testee/` -- thin bounded blocking and neutral-process adapters over
  the same driver/core behavior.
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
