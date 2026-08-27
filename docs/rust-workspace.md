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
- No WebSocket behavior exists: every module in `ws-core` is an
  empty, documented placeholder marked UNIMPLEMENTED.
- No performance representation of any kind is made. No benchmark sample was
  collected, no tuning performed.
- US-009 AC1 status (updated with the AC1 infrastructure round): the
  **workspace-gate half of AC1 is now configured** — forbid(unsafe_code)
  enforcement, the dependency-unsafe inventory, formatting, Clippy with
  warnings denied, debug/release tests, MSRV, license, audit, and
  reproducible-lockfile gates, plus good/bad scaffold canaries, all wired
  into `make -C rust gates` (see "AC1 workspace gates" below). The
  **sbx-execution half of AC1 is NOT claimed**: executing every build.rs,
  proc macro, dependency build, audit tool, and project test through the
  accepted US-007 Docker sbx workload profile before artifacts are promoted
  out remains a parent-run sandbox step that has not happened here. The
  separately authorized repository handoff clause of AC1 is likewise outside
  this round and is not claimed by it.

## Toolchain pin

`rust/rust-toolchain.toml` pins channel `1.95.0`, matching the
digest-qualified intake pin in `evidence/intake/toolchain-pins.json`
(`rustc-1.95.0-aarch64-apple-darwin`). A unit test inside `ws-core`
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
| `ac1-gates` | `go run ./cmd/rustgatectl -root .` (the seven AC1 workspace gates below) |

## AC1 workspace gates (`make -C rust ac1-gates`)

The US-009 AC1 infrastructure round added `cmd/rustgatectl` (Go, the repo's
incumbent tooling; unit polarity tests in `cmd/rustgatectl/main_test.go`),
invoked by `make -C rust ac1-gates` and therefore by `make -C rust gates`.
The runner reads every completed command's exit code from its process state
— success and failure alike — and prints it verbatim
(`gate=... step=... exit=N`; a command that never produced a process state
is reported as `exit=none process_state=absent` with the error, never as an
invented number) and exits nonzero if any gate fails:

1. **forbid-unsafe** — discovers every first-party lib and bin crate root
   via `cargo metadata` and fails unless each root carries a real
   crate-root `#![forbid(unsafe_code)]` inner attribute. The scan is
   tokenizer-grade: line comments, nested block comments, and
   string/raw-string literals are skipped rather than matched, and the
   attribute only counts before the first non-attribute, non-comment token
   — a mention inside a comment, a literal, or a nested `mod` never
   satisfies the gate.
2. **dependency-inventory** — the workspace is dependency-free by design;
   the gate mechanically asserts `cargo metadata --locked` reports zero
   non-path dependencies and that the committed machine-readable inventory
   (`rust/gates/dependency-unsafe-inventory.json`, currently the stated
   empty inventory) agrees. Any future external crate fails the gate until
   a reviewed entry with a non-blank `unsafe_usage` statement lands there.
   Entries bind the reviewed identity `name@version@source`: `source` is
   required on every entry, and the same name and version arriving from a
   different source fails until a renewed reviewed entry lands; stale
   entries also fail.
3. **msrv** — asserts `rust-toolchain.toml` channel, workspace
   `rust-version`, and the intake-qualified rustc version
   (`evidence/intake/toolchain-pins.json`) are all `1.95.0`, that every
   member inherits or matches it **under its `[package]` section**
   (section-aware TOML walk — a decoy under `[package.metadata.*]` does not
   count), and runs
   `rustup run 1.95.0-… cargo check --workspace --all-targets --locked` —
   because the MSRV equals the pinned toolchain, that check IS the
   build-under-MSRV. Building under the MSRV toolchain is a hard
   requirement: if that toolchain is not installed the gate FAILS rather
   than passing pending. Honest limit: no installed toolchain is older
   than the MSRV, so only the below-MSRV differential build is recorded as
   pending toolchain availability, not claimed. The license member check
   uses the same section-aware walk.
4. **license** — stated policy: root `LICENSE` (Apache-2.0) plus per-crate
   SPDX `license = "Apache-2.0"` via workspace inheritance; per-source-file
   headers are not required. The gate checks the root file's Apache-2.0
   header and every member's field.
5. **audit** — probes `cargo-audit` and `cargo-deny` on PATH (recorded
   verbatim) and runs whichever is present. Honest limit: neither tool is
   installed on this host; with zero non-path dependencies the audit
   surface is empty, so the zero-dependency assertion is the effective
   check and tool execution is recorded pending availability. If a
   dependency ever appears while no tool is installed, the gate FAILS.
6. **lockfile** — `cargo build --workspace --locked` plus
   `cargo metadata --locked` must succeed, `Cargo.lock` must be
   byte-identical before/after, and `git diff --exit-code -- rust/Cargo.lock`
   must be clean.
7. **canaries** — two standalone fixture crates outside the workspace
   (`rust/gates/canaries/good-scaffold`, `…/bad-scaffold`, excluded in
   `rust/Cargo.toml`). The good one must pass the forbid scan, clippy
   `-D warnings`, and its tests; the bad one (missing forbid attribute,
   first-party `unsafe`, deliberate clippy violation) must FAIL the scan
   and clippy. The gate fails on any inversion — the polarity proof that
   the gates can still both accept a conforming scaffold and reject a
   broken one.

The sbx-execution half of AC1 (all of the above executing through the
accepted US-007 Docker sbx workload profile before artifact promotion) is
**not** performed by `rustgatectl` and remains an open parent-run step.

## Safety and dependency policy

- Every first-party crate carries `#![forbid(unsafe_code)]` (PRD gate) and
  `#![deny(missing_docs)]` so the eventual public contract arrives
  documented. A smoke test (`ws-core/tests/scaffold_smoke.rs`) parses
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
| US-009 | `ws-core` crate (library namespace `ws_core`): the `ConnectionCore` contract types in `src/connection.rs` (config/role/commands/writes/events/state/failures), plus workspace gates. Crate naming is decided: the owner decision of 2026-08-27 (us009_crate_naming = ws_core) fixed the migration map's `ws_core::` namespace as canonical, and the crate is named to match; the PRD `files` list's sketched root-level `crates/websocket-core` is superseded by that decision. |
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
  `Makefile`, `README.md`, `ws-core` crate (scaffolded as `connection-core`,
  renamed to `ws-core` once the owner crate-naming decision landed) with
  doc-only modules and smoke tests.
- `.gitignore`: appended explicit `rust/` target-directory entries.
- `docs/rust-workspace.md` (this file).

Nothing under `evidence/`, `internal/`, `cmd/`, `schemas/`, `terraform/`,
`.github/`, `java-oracle/`, `benchmarks/`, the root `Makefile`, or
`.dialed.yml` was touched, and the Go module builds and tests unchanged.

## What the US-009 AC1 infrastructure round changed

- `cmd/rustgatectl/` (new): the AC1 gate runner and its polarity unit tests.
- `rust/gates/dependency-unsafe-inventory.json` (new): the committed, stated,
  machine-readable dependency-unsafe inventory (empty by design).
- `rust/gates/canaries/{good,bad}-scaffold/` (new): the standalone scaffold
  canary fixture crates (with committed trivial `Cargo.lock`s).
- `rust/Cargo.toml`: `exclude` entries for the canary crates.
- `rust/Makefile`: `ac1-gates` target, added to `gates`.
- `docs/rust-workspace.md`: this update.

No `ws-core`, `ws-oracle-harness`, or `candidate-stub` source or manifest was
modified (MSRV and license were already declared via `[workspace.package]`
inheritance), so the digest-frozen US-006 fixture catalog was untouched and
`go test ./internal/formalplan/` passes unchanged.
