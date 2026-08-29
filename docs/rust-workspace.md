# Rust workspace: scope, gates, and story mapping

Status: **US-009 through US-018 are shipped; US-019 provides inert conformance
readiness; US-020 adds the bounded neutral differential process seam; US-024
ships the owner-relaxed private output-lifecycle refinement; US-025 ships only
the owner-relaxed resource-decision mechanics outside the Rust crates; US-026
ships only deterministic fixture-rehearsal mechanics outside the Rust crates;
US-027 ships only owner-relaxed public-projection mechanics outside the Rust
crates. All 27 PRD stories are execution-complete under mixed inherited,
borrowed, independent, and owner-relaxed scopes, but the original strong
success criteria are not satisfied.**
The `rust/` workspace contains the dependency-free Sans-I/O `ConnectionCore`,
the single-owner driver, and the thin blocking and one-record neutral adapters.
US-024 centralizes the driver's pending-output and partial-write state in a
private `OutputLedger` without changing public declarations or the core
contract. US-025 retains absent raw ledgers, unbound hosts, and
`INCONCLUSIVE_BLOCKED` measurement acceptance. US-026 retains
`CUTOVER_BLOCKED`, no live traffic/effects, and no production-shaped rehearsal.
US-027 retains `INDEPENDENT_ACCEPTANCE_BLOCKED`, declares its checkout
`NOT_VERIFIED`, and makes no independent-acceptance or external-publication
claim. No performance, cutover-readiness, or strong project-acceptance
representation is authorized beyond the recorded mechanics.

**Explicit non-claims:**

- US-020 extends protocol behavior only with outbound fragmented sends. Exact
  consumption/buffer accounting and frame traces are read-only observations
  at the existing decoder/encoder seams.
- `websocket-testee neutral-oracle --protocol NDRV1` is a strict, bounded,
  dependency-free process codec over `ConnectionOwner`; it is not another
  WebSocket parser or state machine. It uses `Rfc6455Strict` unless the caller
  explicitly supplies `--behavior-profile java-websocket-1.6.0`.
- `BehaviorProfile::Rfc6455Strict` remains the default for RFC, security, and
  canonical evidence gates. `JavaWebSocketV1_6_0` is an opt-in source-fidelity
  surface. A fresh no-write public diagnostic executed 74 scenarios through
  both live processes twice (296 receipts) with 74 stable exact normalized
  agreements and zero field mismatches. This is public-corpus, owner-attested
  behavioral evidence, not hidden/independent acceptance or a blanket API,
  performance, platform, and integration parity claim.
- No performance representation of any kind is made. No benchmark sample was
  collected, no tuning performed.
- No fresh Autobahn run, Linux run, publication, production, hidden-corpus, or
  independent-review claim is made by this workspace. The no-write public
  parity diagnostic does not replace the canonical strict differential receipt.

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
| US-026 | **Owner-relaxed cutover-rehearsal mechanics complete outside the Rust crates.** Fixed fixtures exercise shadow/canary/fallback/reconciliation/rollback/soak state transitions, while all 12 live/production blockers remain and `CUTOVER_READY` is unreachable. |
| US-027 | **Owner-relaxed public-projection mechanics complete outside the Rust crates.** The declared checkout remains `NOT_VERIFIED`; 26/26 child mechanics entries and 24/24 blocked formal obligations project locally while `INDEPENDENT_ACCEPTANCE_BLOCKED` remains authoritative. |

## US-027 final projection

The final evaluator/tooling commit is
`1b3da7976848e949cc10fd23aa6f56031a494529`, with tree
`325f2e20bf59513bc2564fc37d1233495347fc25`. It truthfully records
`PASS_OWNER_RELAXED_PUBLIC_PROJECTION_MECHANICS` under
`OWNER_ATTESTED_NOT_INDEPENDENT`, with `independent_review_claimed:false` and
`INDEPENDENT_ACCEPTANCE_BLOCKED`. The declared, but not verified, subject is
commit `98ddff676fe336e22ca9ae4ee7b6f8c6c9025ddc` and tree
`36ee700401268621aae58639185dcdc11e4c00c6`.

The evaluator binds projection contract root
`sha256:08c14048d92b1066ad5f459d3e41e69d6e7a7cb81e8524c9c1cf06382c59f195`,
input root `sha256:93d41275b7600583d71bf4985cd4be7301122496419d1cde4fc09aa1850f475b`,
candidate root `sha256:dd96c5fb0346f736e6ddadf7848d34ceb5e4c2beefe77c1730bec6649516190e`,
and public projection root
`sha256:e77e3ea6e5169806144d8bc46354a0f2939e764c6a92bf97999109a58296f8b0`.
The digest-bound contract remains byte-for-byte unchanged after shipment.

The seven write-once outputs are:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `assurance/independent-replay.json` | 9,769 | `sha256:d2e63736c9672003460491dd58db97775f4b27e3597489b2406cfa221db265a3` |
| `assurance/receipts/human.json` | 990 | `sha256:1af7fbf487b4720af9598de0d80c32129c67778860e42c903229efc72bd0e871` |
| `assurance/receipts/codex.json` | 1,020 | `sha256:803ee0637bf01c36d9e06811001b82bb0b81b12c16c4f9dd812d00ec5e4408be` |
| `assurance/receipts/reality.json` | 1,024 | `sha256:a3e1029458fdb842bd1419dc4b3305bfb26fa3be742bfa01f60e20323f323dc7` |
| `public/formal-coverage.md` | 1,401 | `sha256:798366d035d33a940568f41b65a59c7bf5c13123cc3a2ca956400addbdf8779a` |
| `public/README.md` | 393 | `sha256:6ae5fed31aa0d8519ab871a024ec6e8a4b0fffdcfbea07c4fedf5e81f9a90bab` |
| `public/snapshot.json` | 1,699 | `sha256:384a9387c227da870bb15b286cf88613fa5c3095ca97f0db795c59f7ca032e5b` |

Two pre-review blockers were closed: runtime and public output were downgraded
from an unverified subject-pinned claim to explicit declared-checkout
nonverification, and the projection contract became an exact held input. The
sole full comments-only review found zero blockers, retained two important
findings, and retained no nits. The remaining important findings are that the
mutation matrix is representative rather than exhaustive and that lock/temp
pathname cleanup is not inode-owned, without a demonstrated cooperative
acceptance bypass. Focused QA passed eight tests; the broader unrelated failures
were the historical workspace qualification binding and sandbox-denied Autobahn
relay socket tests. Clean-clone reality validation passed at the exact final
head/tree.

All 14 strong blockers and seven exact nonclaims in
`docs/us027-independent-projection-contract.md` remain authoritative. In
particular, the result does not verify that the supplied checkout equals the
declared subject, provide a provenance-distinct custodian or human/protected
replay, strongly accept every child gate or formal obligation, accept measured
performance or live cutover, publish or sign externally, deploy to production,
or authorize Java removal.

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
