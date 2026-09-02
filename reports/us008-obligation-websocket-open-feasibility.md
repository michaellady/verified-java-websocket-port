# DRAFT FEASIBILITY ASSESSMENT — NOT DISCHARGED — Kani unavailable on host — does not satisfy any gate

Obligation: `surface.websocket-open`
Worktree: `/Users/mikelady/hq/workspace/worktrees/vjwp-obl-websocket-open`
Branch: `codex/us008-obl-websocket-open`, based on `codex/race-catchup` @ `357e5c5`
Date: 2026-09-02

**Nothing in this memo is a proof claim.** No harness was written. No evidence file,
catalog, or PRD was modified. Kani is absent from this host, so no solver was run and
no solver cost was measured. Every cost statement below is either a citation of a
retained artifact, a citation of master-PRD prose, or an explicitly-labelled structural
argument — never a measurement I performed.

---

## 1. The catalog entry

`assurance/formal/obligation-catalog.json`, obligation 24 of 24:

```json
{
  "obligation_id": "surface.websocket-open",
  "surface_ids": ["surface.websocket-open"],
  "statement": "The declared WebSocket opening seam enters the shipped connection core.",
  "normative_refs": ["RFC6455"],
  "required_strength": "PRODUCTION_REFINEMENT",
  "allowed_methods": ["BOUNDED_MODEL", "KANI", "TLA_PLUS"],
  "required_evidence_kinds": ["MUTATION_SENSITIVITY", "PRODUCTION_LINKAGE"],
  "required_mutation_ids": ["invalid-frame-rejection-relabeled"]
}
```

The catalog's own `rust_bindings` entry names the seam symbol:

- `production_symbol`: `websocket_core::ConnectionCore::step`
- `source_path`: `rust/connection-core/src/connection.rs`
- `reachable_from_entry`: `false`, `connection_state`: `DISCONNECTED`
- `blocker_ids`: `["blocker-formal-refinement"]`

The catalog's `evidence` entry is `execution_state: NOT_EXECUTED`, `observed_strength: NONE`,
`refinement.state: DISCONNECTED`, bounds both `null`, assumptions both `UNRESOLVED`.

**Finding 1 (mutation evidence is self-declared non-binding).** The catalog's own evidence
entry records the required mutation as:

```json
"mutation_sensitivity": [
  { "mutant_id": "invalid-frame-rejection-relabeled",
    "anchor": "1ff89fa30cb0ab6ff339afd3ce486a36e9f7f325",
    "disposition": "RETAINED_KILLED_DIFFERENT_SUBJECT" }
]
```

`RETAINED_KILLED_DIFFERENT_SUBJECT` is the catalog stating that this mutant was killed
against something other than this obligation's subject. Confirmed in `mutation/plan.json`:
`invalid-frame-rejection-relabeled` is a **Java** mutant (`"runtime": "java"`), planted in
`java-oracle/src/main/java/OracleEngine.java`, killed by `OracleMainTest.invalid-frame`, and
recorded `KILLED` in `mutation/denominator.json`. It touches no Rust symbol and no
handshake code. The catalog's `required_mutation_ids` for this obligation therefore cannot,
even in principle, demonstrate sensitivity of the handshake-to-open seam.

---

## 2. What has already been attempted

### 2.1 The projection ladder: this obligation never qualified at any rung

All seven retained projections were read. `surface.websocket-open` is identical in every one:

| projection | proof subject | rust | mutation | aggregate |
|---|---|---|---|---|
| `kani-coverage-0cf36a9.json` | 0cf36a9 | BLOCKED | BLOCKED | BLOCKED |
| `kani-coverage-17e92c5.json` | 17e92c5 | BLOCKED | BLOCKED | BLOCKED |
| `kani-coverage-467a224.json` | 467a224 | BLOCKED | BLOCKED | BLOCKED |
| `kani-coverage-e624399.json` | e624399 | BLOCKED | BLOCKED | BLOCKED |
| `kani-coverage-2531f12.json` | 2531f12 | BLOCKED | BLOCKED | BLOCKED |
| `kani-coverage-a2b00ef.json` | a2b00ef | BLOCKED | BLOCKED | BLOCKED |
| `kani-coverage-30ee613.json` | 30ee613 | BLOCKED | BLOCKED | BLOCKED |

Blocker ids at every rung include `blocker-kani-mutation-coverage` (`RUST_MUTATION_KANI_ABSENT`)
and `blocker-kani-production-coverage` (`RUST_PRODUCTION_KANI_ABSENT`). The ladder rose
11 → 14 → 16 → 17 → 18 → 19 of 24 without ever touching this obligation.

### 2.2 The 16 retained harnesses: none targets `connection.rs`

`evidence/formal/kani-30ee613/summary.json` lists 16 harnesses. Their `source_path` values
are exactly `frame/decode.rs`, `frame/mask.rs`, `frame/encode.rs`, `fragment.rs`, `control.rs`,
`close.rs`, `utf8.rs`. **No retained harness has ever had `rust/connection-core/src/connection.rs`
as its source path, and no retained harness has ever named `ConnectionCore::step` as its
target symbol.** The `subject.sources` digest list in the same receipt contains seven files
and `connection.rs` is not among them.

Unwind bounds actually used, and check counts (run-1):

| harness | unwind | checks |
|---|---|---|
| `frame::decode::proofs::prove_two_byte_protocol_fault_classification` | 12 | 1275 |
| `fragment::proofs::prove_binary_continuation_assembly` | 12 | 1543 |
| `control::proofs::prove_ping_pong_policy_and_encoding` | 12 | 1127 |
| `close::proofs::prove_close_machine_terminal_lifecycle` | 8 | 914 |
| `frame::encode::proofs::prove_short_frame_octets_and_masking` | 12 | 882 |
| `utf8::proofs::prove_strict_utf8_exact_len_le_4` | 6 | 476 |
| `close::proofs::prove_close_code_classification` | 2 | 398 |
| `frame::mask::proofs::prove_mask_involution` | 9 | 105 |
| (8 further decode harnesses) | 12 | 334–487 |

**The maximum unwind bound ever used anywhere in this program is 12.** Every qualified
harness uses exact, small lengths (`0..4`, `0..2`, `0..125`), never a symbolic length.

### 2.3 The recorded composition attempts and the nonclaims

From the master PRD `userStories[12]` (US-008) notes at
`/Users/mikelady/hq/companies/enterprise-vibe-code/projects/verified-java-to-rust-port/prd.json`,
verbatim:

> "Full ConnectionCore::step and direct consume_frames control compositions each crossed the
> declared ten-minute ceiling without a verdict and receive no proof credit."
> — 2026-08-29 control proof-ladder expansion (receipt 2531f12)

> "Decoder/event wiring, public step accounting, and handshake-to-open composition remain
> explicit nonclaims." — same entry

> "ConnectionCore decoder and output wiring remain explicit nonclaims."
> — 2026-08-29 close-terminal lifecycle expansion (receipt a2b00ef)

> "Extended-length contents, payload semantics, ConnectionCore terminal wiring, Java proof,
> refinement, and independence remain explicit nonclaims."
> — 2026-08-29 typed protocol-fault expansion (receipt 30ee613)

Two further cost anchors from the same notes:

> "The new FrameEncoder::encode harness proves emitted frame octets and masking for every
> payload byte at lengths 0..4 ... and cost about 307 seconds per focused pass under an
> explicit ten-minute ceiling." (receipt 467a224)

> "Its initial unwind-eight assertion failure remains adverse evidence; only the full
> unwind-twelve rerun qualified." (receipt e624399, fragment harness)

So the two directly relevant prior attempts are: (a) full `ConnectionCore::step`, (b) direct
`consume_frames`. Both crossed the ceiling without a verdict. Under rule W20 those are
FAILED evidence, and the completed `control` rung cannot inherit them. **The handshake-to-open
composition specifically is named as a standing nonclaim and, as far as the retained record
shows, was never separately attempted at all** — it is listed as a nonclaim rather than as a
timed-out attempt.

### 2.4 Finding 2 — the timeout claims are not machine-verifiable (observability gap)

The "ten-minute ceiling" cannot be confirmed from any artifact in this lane. Verified in code:

- `cmd/kanidriver/main.go:613` `executeHarness` — on timeout it returns before writing
  anything: `if processCtx.Err() != nil { return kaniResult{}, processCtx.Err() }`. The
  normalized-log write happens *after* that guard, so a timed-out harness retains **zero bytes**.
- `cmd/kanidriver/main.go:343-347` — the generate loop returns `receipt{}, fmt.Errorf(...)`
  on any harness error, aborting the **entire** receipt. There is no negative-record path.
- `cmd/kanidriver/main.go:179` — `--timeout` default is **5 minutes**, not ten.
- `cmd/kanidriver/main.go:275` — hard bound is `(0, 15m]`, not ten.
- `evidence/formal/kani-30ee613/summary.json` limitations: *"Normalized logs retain semantic
  results and raw-output digests but intentionally omit host paths and elapsed times."*

The ten-minute figure is therefore neither the default nor the maximum; it was a per-run CLI
argument that no retained artifact records. **The claim that the `ConnectionCore::step` and
`consume_frames` compositions crossed a ten-minute ceiling rests on master-PRD prose alone and
is not reproducible from evidence.** This does not make the claim false — it makes it
unfalsifiable from the artifact set, which is itself a defect in the evidence lane. Recommend
a negative-evidence envelope (harness id, wall clock, ceiling, `TIMEOUT` disposition) that is
retained rather than discarded, so a ceiling crossing becomes citable FAILED evidence instead
of prose.

### 2.5 Finding 3 — the projection credits obligations by self-declared label, not by symbol

`cmd/kanidriver/coverage.go:314-322`, `deriveCoverage`:

```go
rustCovered := map[string]bool{}
for _, harness := range value.Execution.Harnesses {
    for _, obligationID := range harness.ObligationIDs {
        rustCovered[obligationID] = true
    }
}
```

The only subsequent validation is that the obligation id exists in the catalog
(`"Kani harness references obligation outside catalog"`). **There is no check anywhere that
`harness.TargetSymbol` matches the catalog's `rust_bindings[obligation].production_symbol`.**

The consequence is material. Nine catalog obligations bind to `websocket_core::ConnectionCore::step`:
`surface.close.status-code`, `surface.close.terminal-state`, `surface.control.ping-pong`,
`surface.fragmentation.continuation`, `surface.handshake.client-request`,
`surface.handshake.server-response`, `surface.messages.binary`, `surface.messages.text-utf8`,
and `surface.websocket-open`. Six of those nine are already credited `rust_status: SATISFIED`
in `kani-coverage-30ee613.json` — by harnesses that target leaf helpers
(`close::CloseMachine lifecycle`, `close::validate_code`, `control::is_observed_control+...`,
`fragment::FragmentAccumulator::plan+prepare+feed+commit`, `utf8::Utf8Validator::feed+finish`)
and never touch `ConnectionCore::step`.

**This is the tempting illegitimate route for my obligation, and I am naming it rather than
taking it.** Adding a `harnessPlan` entry whose `ObligationIDs` contains `"surface.websocket-open"`
would flip this obligation to `SATISFIED` in the projection with no proof of the seam whatsoever.
That is precisely the inheritance rule W20 prohibits. It is also, on the evidence above,
approximately what already happened for six sibling obligations — which is a finding the
program should adjudicate independently of my obligation.

---

## 3. The shipped production symbols forming the handshake-to-open seam

Public entry: `pub fn step(&mut self, input: CoreInput<'_>) -> StepResult` —
`rust/connection-core/src/connection.rs:1049`. This is the only mutating core operation.
It wraps `step_protocol` and records `StepAccounting { pre_state, post_state, bytes_consumed,
wire_buffered_bytes, message_buffered_bytes }` into `last_step_observation`.

**Client half** — `connection.rs:1357-1397`, inside `step_protocol`:

```rust
if let CoreInput::Transport(bytes) = input
    && self.role == Role::Client
    && self.state == ConnectionState::Connecting
    && self.client_handshake.has_started()
{
    match self.client_handshake.consume_response(bytes.as_slice()) {
        ClientResponse::Opened(descriptor) => {
            self.state = ConnectionState::Open;
            debug_assert_eq!(self.state, ConnectionState::Open);
            return StepResult {
                outputs: Box::new([
                    CoreOutput::StateChanged(ConnectionState::Open),
                    CoreOutput::SemanticEvent(SemanticEvent::ClientHandshakeOpened { descriptor }),
                ]),
                failure: None,
                state: self.state,
            };
        }
        ...
```

**Server half** — `connection.rs:1399-1441`: identical shape via
`self.server_handshake.consume_request(bytes.as_slice())`, `ServerRequest::Opened { descriptor, response }`,
emitting three outputs in order: `TransportWrite(response)`, `StateChanged(Open)`,
`SemanticEvent::ServerHandshakeOpened { descriptor }`.

Supporting shipped symbols on the path:

| symbol | file | note |
|---|---|---|
| `ClientHandshake::start(descriptor, nonce: [u8;16], max_bytes, max_line, max_headers)` | `handshake/client.rs:99` | computes `expected_accept` once |
| `ClientHandshake::consume_response(&mut self, &[u8]) -> ClientResponse` | `handshake/client.rs:154` | |
| `ServerHandshake::consume_request(&mut self, &[u8]) -> ServerRequest` | `handshake/server.rs:71` | |
| `ResponseParser::consume(&mut self, &[u8], &[u8;28]) -> ParseProgress` | `handshake/http.rs:43` | |
| `HeadAccumulator::consume(&mut self, &[u8]) -> HeadProgress` | `handshake/http.rs:74` | per-byte scan loop |
| `validate_response(&[u8], &[u8;28]) -> Result<(), HandshakeFailure>` | `handshake/http.rs:147` | header walk |
| `duplicate_before(&[u8], usize, usize, &[u8]) -> Result<bool, _>` | `handshake/http.rs:244` | rescan-per-header |
| `crypto::derive_accept(&[u8;24]) -> [u8;28]` | `handshake/crypto.rs:84` | two SHA-1 compressions |
| `crypto::canonical_nonce_key(&[u8]) -> Result<[u8;24], _>` | `handshake/crypto.rs:28` | base64 decode + re-encode check |

Note that `ClientHandshake`, `ServerHandshake`, `ResponseParser`, `HeadAccumulator` and the
`crypto` functions are all `pub(crate)`. Only `ConnectionCore::step` is public. A harness
placed inside the crate can reach the `pub(crate)` items; the incumbent pattern does exactly
this (`#[cfg(kani)] mod proofs` inside each module).

---

## 4. Barrier diagnosis

The barrier is **both**, and the two parts have different owners. Separating them is the
main analytic result of this memo.

### 4.1 The solver-cost barrier is real, is specific, and is probably surmountable

Four cost drivers, each read from source:

**(a) SHA-1 over a symbolic message — `crypto::derive_accept`, `crypto.rs:84-149`.**
Two full 64-byte compressions (`sha1_compress(&mut state, &padded[..64])` and `[64..]`),
each 80 rounds of `rotate_left` / `wrapping_add` / bitwise selection over `u32`, plus a
64-word message expansion `words[i] = (w[i-3]^w[i-8]^w[i-14]^w[i-16]).rotate_left(1)`.
Symbolic SHA-1 is a classic worst case for bit-blasting SAT backends.
*This driver is avoidable on the client path.* The nonce is a caller-supplied parameter of
`LocalCommand::StartClientHandshake { descriptor, nonce: [u8;16] }` (`connection.rs:425-429`).
A harness may legitimately fix the nonce concrete; CBMC then constant-folds `derive_accept`
entirely, while the *response bytes* stay symbolic. **On the server path it is not avoidable**:
the key arrives inside the symbolic request headers, so `canonical_nonce_key` + `derive_accept`
run over symbolic input. Client-first decomposition is strongly indicated.

**(b) Loop bound ~10× beyond anything ever used.** To reach `Opened`, `HeadAccumulator::consume`
(`http.rs:75`, `for (index, &byte) in bytes.iter().enumerate()`) must traverse a complete
response head. The minimum valid 101 response — status line, `Upgrade`, `Connection`,
`Sec-WebSocket-Accept: <28 bytes>`, terminator — is roughly 130 bytes. Unwind must exceed that.
The maximum unwind ever used in this program is 12, and the fragment harness already *failed
its unwinding assertion at 8* before qualifying at 12 (PRD, receipt e624399). A jump from 12
to ~130 is not incremental.

**(c) A quadratic symbolic rescan.** `validate_response` (`http.rs:157`) walks headers with
`while cursor < headers_end`, and for each header calls `duplicate_before(bytes, first_header, cursor, name)`
(`http.rs:244`), which itself loops `while cursor < stop` re-scanning every preceding header
with `find_crlf` and `ascii_eq`. Over symbolic bytes this is an O(n²) branch explosion on top
of (b).

**(d) Default limits are large.** `ConnectionLimits::default()` (`connection.rs:111-113`) is
`handshake_bytes: 4_096`, `handshake_header_count: 32`, `handshake_header_line_bytes: 512`.
Worst case inside the parser is 32 × 512. `ConnectionConfig` is caller-supplied, so a harness
may shrink these — but doing so *changes the proved bound* and must be declared in the
symbolic domain, not quietly assumed.

Why I judge this part surmountable: the program's own qualified harnesses all resolve exactly
this class of problem by enumerating **exact lengths** instead of symbolic ones
(`"all payloads of exact lengths 0..4"`, `"all control payloads of exact lengths 0..4"`,
`"all initial binary fragments of exact lengths 0..2"`). A concrete-length response skeleton
with symbolic *values* in the decision-relevant fields keeps a genuine symbolic domain while
collapsing (b), (c) and (d) to constant-propagated straight-line code. A peer agent reports a
sibling-plane precedent (symbolic-length slice failing its unwinding assertion at `--unwind 16`
after 924 s; four concrete-length harnesses each verifying in under a minute at identical
coverage). **I did not observe that precedent and cannot confirm it** — I record it as
peer-reported, not as measurement.

**I cannot measure any of this.** Kani is absent (§6). Every statement in §4.1 is a structural
reading of source plus citation of retained receipts. No number here was produced by a solver
run on this host.

### 4.2 The structural barrier is unconditional and is not mine to remove

Even a perfect, fast, honest harness cannot reach `PRODUCTION_REFINEMENT` for this obligation.
Three independent mechanisms, all verified in code:

**(i) The projection hardcodes refinement to zero.** `cmd/kanidriver/coverage.go:379` sets
`RefinementSatisfied: 0` as a literal in the `coverageCounts` struct, and line ~369 sets every
row's `RefinementStatus: coverageBlocked` unconditionally. No harness can move it.

**(ii) The frozen validator rejects any connected Rust binding.**
`internal/assurance/candidate.go:567`, in `validateFormalSemantics`:

```go
if rustBinding.ConnectionState != "DISCONNECTED" || rustBinding.ReachableFromEntry ||
   !contains(rustBinding.BlockerIDs, "blocker-formal-refinement") || ... {
    return errors.New("RUST_PRODUCTION_LINKAGE_OVERCLAIM")
}
```

The catalog lists `PRODUCTION_LINKAGE` as a `required_evidence_kind` for this obligation, while
the validator fails closed on any binding that actually asserts linkage. The required evidence
kind and the validator are in direct contradiction.

**(iii) The validator also rejects honest bounds and assumptions.** Same function, immediately
below:

```go
if evidence.Bounds.MaxFrameBytes != nil || evidence.Bounds.MaxSteps != nil ||
   evidence.Assumptions.Role != "UNRESOLVED" || evidence.Assumptions.Allocator != "UNRESOLVED" {
    return errors.New("FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE")
}
```

Any real bounded harness for this seam necessarily has a step/byte bound and a **resolved role**
— the client and server halves are different code paths, so role resolution is the whole point.
Recording that honestly in the catalog makes the catalog invalid. All 24 evidence entries are
currently `NOT_EXECUTED / NONE / DISCONNECTED / UNRESOLVED / null / null`; the validator can only
accept them in that shape.

**Conclusion.** `required_strength: PRODUCTION_REFINEMENT` for `surface.websocket-open` is
**structurally unmet and unmeetable within the current lane**, for reasons entirely independent
of solver cost and entirely outside the scope of a harness-writing task. Closing every remaining
composition in the program would still leave `refinement_satisfied` and `aggregate_satisfied` at
exactly `0/24`. The only quantity a harness can move is `rust_satisfied` (and `mutation_satisfied`),
which earns a **bounded** label, not a refinement label.

---

## 5. Ranked routes

Assurance labels are the honest label each route would actually earn, against
`required_strength: PRODUCTION_REFINEMENT`.

### Route 1 — Client-half seam harness, concrete nonce, concrete-length response, symbolic accept + role
**Technique.** Inside `#[cfg(kani)] mod proofs` in `connection.rs`. Fix the nonce concrete so
`derive_accept` constant-folds. Build a concrete-length (~129-byte) response skeleton whose
`Sec-WebSocket-Accept` field is 28 symbolic bytes. Drive `ConnectionCore::step` with
`CoreInput::Command(StartClientHandshake{..})` then `CoreInput::Transport(response)`. Assert the
biconditional: accept-matches ⟺ `state == Open` **and** outputs are exactly
`[StateChanged(Open), ClientHandshakeOpened{descriptor}]` in that order; accept-mismatches ⟹
state is not `Open` and the failure is `HandshakeFailure::AcceptMismatch`. Shrink
`ConnectionLimits` and declare the shrunk values in the symbolic domain.
**Earned label: `bounded`.** Genuine 2^224-value symbolic domain over the exact decision that
gates the transition, at a declared byte bound.
**Satisfies required_strength? NO.** `bounded` < `PRODUCTION_REFINEMENT`. It would move
`rust_satisfied` 19 → 20 in the projection and nothing else.
**Tractability: unknown, plausible.** Unmeasurable here. Highest-value route if Kani returns.

### Route 2 — Route 1 plus a paired exact-source mutation canary
**Technique.** Route 1, plus one exact source mutation on the seam — e.g. in `connection.rs:1371-1373`,
delete `self.state = ConnectionState::Open;` while leaving the emitted `StateChanged(Open)` output
intact, so the announced state and the actual state diverge. Requires a matching `mutationPlan`
entry so `deriveCoverage` credits `mutationCovered`.
**Earned label: `bounded` + differential sensitivity.** Would move both `rust_satisfied` and
`mutation_satisfied` 19 → 20.
**Satisfies required_strength? NO.** Same ceiling as Route 1.
**Note.** This is the only route that produces sensitivity evidence actually bound to this
obligation's subject, which the catalog's own `required_mutation_ids` does not (Finding 1).

### Route 3 — Server-half seam harness
**Technique.** As Route 1 but through `consume_request`, with a symbolic `Sec-WebSocket-Key`.
**Earned label: `bounded`** if it terminates.
**Satisfies required_strength? NO.**
**Tractability: poor.** Symbolic key forces `canonical_nonce_key` (base64 decode plus a full
re-encode equality check, `crypto.rs:28-82`) and then symbolic SHA-1 through `derive_accept`.
Rank below Route 1; attempt only after Route 1 returns a verdict, and consider a concrete key
with symbolic surrounding headers as a cheaper variant.

### Route 4 — TLA+ model of the opening lifecycle
**Technique.** `TLA_PLUS` is an allowed method. There is precedent in-tree (`evidence/formal/tlc-4dc9582`,
and the PRD records "current exact TLA model checks"). Model `Connecting → Open` with accept
validation abstracted to a predicate.
**Earned label: `proved-model`.**
**Satisfies required_strength? NO — and it is the wrong axis.** The obligation statement is
"*enters the shipped connection core*". A TLA+ model proves a property of the model, not of
`connection.rs`. It cannot supply `PRODUCTION_LINKAGE`. Useful as a specification artifact;
worthless as production-refinement evidence. Explicitly do not let a green TLC run be projected
onto this obligation.

### Route 5 — Concrete end-to-end trace through `ConnectionCore::step` under CBMC
**Technique.** Fully concrete valid handshake bytes; assert the transition.
**Earned label: `observed`.** With no symbolic input this is a unit test executed by a model
checker. The existing 224-test Rust suite already covers it.
**Satisfies required_strength? NO.** Adds nothing. Listed only to be explicitly rejected.

### Route 6 — Label a leaf harness with `surface.websocket-open` (REJECTED, NOT A ROUTE)
Per Finding 3 this would mechanically flip the obligation to `SATISFIED` with zero proof of the
seam, because `deriveCoverage` never checks the target symbol. **This is exactly the composition
inheritance W20 forbids. Recorded here so it is visible and refused, not so it is available.**

### Not a route: full symbolic `ConnectionCore::step` or `consume_frames`
Already attempted per the PRD; both crossed the ceiling without a verdict, which is FAILED
evidence under W20. `consume_frames` (`connection.rs:1570`) is a doubly-symbolic loop — symbolic
frame count × symbolic payload length — over `Vec` with `try_reserve_exact` returning
`Box<[CoreOutput]>`. Do not retry as-is.

---

## 6. Harness decision: **none written**

No harness file was created. Two reasons, the first decisive and empirical.

**(a) A Kani harness cannot even be type-checked on this host, so "verified with `cargo check`"
would be a false claim.** Every proof module in this crate is gated `#[cfg(kani)]`
(e.g. `control.rs:192`). Without Kani, `cfg(kani)` is unset and `cargo check` never looks
inside those modules. Verified both directions:

```
$ cargo check -p websocket-core
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.63s

$ RUSTFLAGS="--cfg kani" cargo check -p websocket-core
error[E0433]: cannot find module or crate `kani` in this scope      (×12+)
```

The `kani` library crate is injected by `kani-compiler`, which is absent. A clean `cargo check`
here would prove only that the harness text was *skipped*. Writing a harness and reporting it
"compiles" would be precisely the exit-code-as-proxy failure the program guards against.

**(b) Adding a registry entry would break the existing receipt.** `cmd/kanidriver/main.go:343-347`
aborts the entire receipt if any planned harness errors or fails to pass. A plan entry for a
harness that has never been run would make regeneration of the qualified 19-obligation receipt
fail. With five obligation agents editing the same registry, that is a real collision hazard.

**Kani status.** `kani` and `cargo-kani` are absent from PATH on this host. I did not install
them; this program requires signed, pinned, owner-promoted toolchain acquisition, and an ad-hoc
install would fail its own gate. The retained receipt pins Kani 0.67.0 / CBMC 6.11.0 /
rustc 1.100.0-nightly (2026-08-20) with sha256s for each binary — that is the pin to reacquire
through the owner-promoted path.

### Verbatim registry entry that Route 2 *would* add (not added)

For collision-avoidance across the five obligation agents, this is the exact single line I would
append to `harnessPlans()` in `cmd/kanidriver/main.go` (~line 409-425), plus its symbol const:

```go
const connectionOpen = "websocket_core::ConnectionCore::step"
```

```go
{HarnessID: "connection::proofs::prove_client_handshake_to_open_transition", TargetSymbol: connectionOpen, SourcePath: "rust/connection-core/src/connection.rs", ObligationIDs: []string{"surface.websocket-open"}, Unwind: 160, SymbolicDomain: []string{"concrete client nonce with constant-folded accept derivation", "concrete-length 129-byte response skeleton", "all 28-byte Sec-WebSocket-Accept values", "both endpoint roles", "shrunk handshake limits: 256 bytes, 8 headers, 64 line bytes", "client half only; excludes server request parsing, symbolic Sec-WebSocket-Key, SHA-1 over symbolic input, decoder/event wiring, and public step accounting"}},
```

- **Harness id:** `connection::proofs::prove_client_handshake_to_open_transition`
- **Unwind bound:** `160` (must exceed the 129-byte response; >13× any bound used to date — the
  single largest tractability risk)
- **Mutation id:** `connection-open-state-transition-dropped` — delete `self.state = ConnectionState::Open;`
  at `connection.rs:1372` while leaving `CoreOutput::StateChanged(ConnectionState::Open)` in place
- **Registry file/lines touched:** `cmd/kanidriver/main.go` ~409-425 (`harnessPlans`) and the
  `mutationPlans()` list

---

## 7. Summary of findings for the program

1. `surface.websocket-open` is BLOCKED at all seven retained rungs; no harness has ever had
   `connection.rs` as its source path.
2. The catalog's own required mutation is a **Java** mutant marked
   `RETAINED_KILLED_DIFFERENT_SUBJECT` — it cannot demonstrate sensitivity of this seam.
3. Timeout claims are unfalsifiable from artifacts: timed-out harnesses retain zero bytes and
   elapsed times are deliberately omitted. Recommend a retained negative-evidence envelope.
4. `deriveCoverage` credits obligations by self-declared label with **no target-symbol check**;
   six obligations bound to `ConnectionCore::step` are already credited by leaf-helper harnesses.
   Recommend adding a symbol-binding assertion — independent of this obligation.
5. Barrier is **mixed**: solver cost (surmountable, unmeasurable here) plus an **unconditional
   structural ceiling** — hardcoded `RefinementSatisfied: 0`, `RUST_PRODUCTION_LINKAGE_OVERCLAIM`
   on any connected binding, and `FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE` on any resolved role
   or declared bound.
6. **`PRODUCTION_REFINEMENT` is unmeetable for this obligation in the current lane.** The best
   any harness earns is `bounded`, moving `rust_satisfied` 19 → 20.
7. No harness written; none can be type-checked on this host.
