# US-021 missing fuzz targets — round 1 (branch `claude/us021-missing-targets`)

Recorded 2026-09-02T23:13:03Z from tool output. Host: Linux x86_64, 4 CPUs,
1-minute load average 9.70 (15-minute 21.13) with sibling agents running. Every
exit code below was read from the process, never inferred.

This is a self-review of my own branch, not an independent review.

Continuation of `drafts/self-review/us021-fuzz-pinning-round-1.md`, whose census
this branch was sent to close. Three container restarts have hit this work; two
earlier waves lost everything because nothing was pushed. This one survived
because every step was pushed.

## What the census asked for, and what is now there

| AC2 family | census verdict | now | target |
| --- | --- | --- | --- |
| handshake client | ABSENT (BLOCK) | PINNED | `rust/ws-core/tests/handshake_fuzz.rs` |
| handshake server | ABSENT (BLOCK) | PINNED | `rust/ws-core/tests/handshake_fuzz.rs` |
| frame decode | PINNED | PINNED (unchanged) | `adversarial_fuzz.rs` |
| message/UTF-8 | PINNED | PINNED (unchanged) | `adversarial_properties.rs` |
| fragment/control | SHARED, no dedicated target (NOTE) | PINNED | `rust/ws-core/tests/fragment_control_fuzz.rs` |
| close/EOF | SHARED, no dedicated target (NOTE) | PINNED | `rust/ws-core/tests/close_eof_fuzz.rs` |
| owner-driver schedules | ABSENT (BLOCK) | PINNED | `rust/ws-driver/tests/driver_schedule_fuzz.rs` |

`cmd/fuzzpinctl -check`, exit code read from the process each time:

| point | exit | blocking findings | notes |
| --- | --- | --- | --- |
| start of this task (`1b73f13`) | 1 | 4 | `FUZZ_ENGINE_UNAVAILABLE` + 3× `FUZZ_TARGET_ABSENT` |
| after `11a26fd` | 1 | 1 | engine only; 2 `FUZZ_FAMILY_HAS_NO_DEDICATED_TARGET` NOTEs remained |
| after `c3990ec` | 1 | 1 | engine only; no NOTEs |

**The engine block remains, deliberately.** `cargo fuzz --version` still exits
101; no coverage-guided engine is installed; installing one was out of scope.
It is recorded UNAVAILABLE and it BLOCKS. It is not skipped and it is not
claimed. `fuzzpinctl` was not modified in any commit on this branch — its 25
static polarity fixtures and 5 campaign-runner polarity fixtures both still
pass at exit 0, and `go test ./internal/fuzzpin/` is green.

## What each new target generates

**`handshake_fuzz.rs`** (handshake client + handshake server, 16,300 cases each,
seeds `0xf00d_0001`–`0xf00d_0014`). Two modes: *modeled* heads drawn as a
`HeadModel` (first-line tokens including TAB-padded variants, a header multiset
with duplicate/case-varied/space- and TAB-padded/folded forms, a
correctly-derived-or-near-miss `Sec-WebSocket-Key`/`Accept`, drawn terminators),
rendered to bytes and predicted from the MODEL without re-parsing the rendering;
and *seed-derived* mutants of the committed us010/us011 corpora, which become
generator INPUT instead of fixed expectations. Oracles: no panic under
`catch_unwind`, terminal stickiness, determinism, rechunking invariance over a
projection that recovers `head_len` as an absolute offset, the model
differential, bounded buffering under drawn small budgets.

**`fragment_control_fuzz.rs`** (21,200 cases, seeds `0xfc70_0001`–`0xfc70_0005`).
Draws the SEQUENCE, not the frame: fragments are drawn together from one payload
so reassembly has a right answer. Six families — model differential over drawn
programs with legal controls interleaved and a six-entry violation menu;
control-interleave transparency (the same fragmentation re-run with the controls
MOVED); split-and-rechunk invariance; hostile soup outside the modeled domain;
a program-level shrinker whose 1-minimality is checked; four pinned normal forms.

**`close_eof_fuzz.rs`** (23,000 cases, seeds `0xc10e_0001`–`0xc10e_0004`). Draws
close/EOF/command schedules against a model of Q10/Q11/Q12/Q13/Q14/Q19/Q20,
compared event-by-event AND write-by-write including the exact unmasked outbound
bytes of the echo and of `send_close`; the close-payload parse in isolation at a
fixed state; exactly-once terminal plus post-terminal inertness with a drawn
tail of further inputs; hostile soup over both roles.

**`driver_schedule_fuzz.rs`** (9,000 cases, seeds `0xd21e_0001`–`0xd21e_0003`).
The ws-driver seam AC2 names: a real `ConnectionDriver`, the owner poll loop, a
modeled transport write path. Draws inbound frame bytes built independently of
the shipped encoder, all six `LocalCommand` kinds from two producers over the
bounded `CommandSender`, write progress including deliberate overruns, EOF,
shutdown, and both `AutoResponsePolicy` and both `CloseEchoPolicy` values.

## Shrinkers (AC1 asked for documented shrinkers; `grep -ci shrink` over
`rust/ws-core/tests/` read 0)

Two, each with generator domain, preserved property, reduction, bound and pinned
normal forms stated in source:

1. `handshake_fuzz.rs::shrink_to_1_minimal` — byte-level, over drawn handshake
   heads and seed mutants. Four pinned normal forms, one of which
   (budget-refusal) exists specifically because it cannot shrink by deletion and
   therefore needs the byte-simplification pass.
2. `fragment_control_fuzz.rs::shrink_program` — PROGRAM-level, over
   `Vec<FrameSpec>`. Preserved property: the program is still refused fatally —
   deliberately NOT the particular failure code, because pinning the code would
   refuse reductions that reach the same defect by a shorter route. Two passes
   (frame deletion, payload truncation) to fixpoint, capped at
   `program.len() + 1` rounds, which is a DOMAIN bound, not a liveness guard.

## RED readings — every plant made in shipped source, shown, then removed

Six plants. Five caught, one missed, and the miss is recorded rather than
rounded off. After every plant, `git diff -- rust/ws-core/src` was empty before
the work continued.

| id | plant | this target | `adversarial_fuzz.rs` (the "shared coverage") | elsewhere |
| --- | --- | --- | --- | --- |
| RED-A | ping arm made to clear the fragment accumulator | CAUGHT: interleave-transparency at case 0, plus modeled + shrinker pins (3 of 6 families) | **passed 14/14** | `fragmentation.rs` 1, `ping_pong.rs` 1 |
| RED-B | `CONTROL_PAYLOAD_LIMIT` 125 → 126 | **MISSED** | passed | **missed by the entire ws-core suite** |
| RED-C | 1002 rejection of an unfragmented data frame during an open sequence, deleted | CAUGHT: modeled at case 2 + shrinker pins | **passed 14/14** | `fragmentation.rs` 1 |
| RED-D | Q10 echo made to carry the WIRE payload, not `[0x03, 0xe8]` | CAUGHT: parse-differential at case 2, modeled at case 6 | **passed 14/14** | `close_eof.rs` 1 |
| RED-E | `handle_eof` Q20 arm made to report 1006 unconditionally | CAUGHT: modeled + inertness at case 6 | **passed 14/14** | `close_eof.rs` 4 |
| RED-F | `closed`-state refusal of a non-empty chunk, deleted | MISSED, then CAUGHT after fixing the test | — | `core_semantics.rs` 1 |

Two of these deserve more than a table row.

**RED-B was missed by everything, and the reason is that the check it mutates is
unreachable.** A control frame whose payload exceeds 125 bytes needs an
extended-length marker, and `decode_frame_header` rejects
`is_control() && marker >= 126` at the length site BEFORE the
`payload_len > CONTROL_PAYLOAD_LIMIT` comparison; with a marker below 126 the
length is at most 125, so the comparison can never be true. The constant is dead
at that site and no test can distinguish 125 from 126 there. I did not change
shipped source over this: the behavior is correct, the redundant site
deliberately mirrors Java's call sites, and deleting a Java-mirroring call site
to improve my own RED reading would be worth less than the reading. It is
recorded in the target's header, and `Violation::OversizedControlPayload` is
named for what it draws rather than for what rejects it.

**RED-F was missed because my test was wrong, not because the defect was
subtle.** The post-terminal inertness family clamped its baseline to `head_len`
instead of `head_len - 1`, which silently pulled the FIRST post-terminal step
INTO the baseline and made the comparison vacuous for exactly the step that
mattered. That is the same defect class as the one this program keeps filing: a
check that cannot fail is not a check. Fixed, and the plant is then caught with
"input 3 after the terminal was not a typed StateViolation".

## Deletion attacks on my own oracles

An oracle nobody removed is an oracle nobody measured.

| attack | result | verdict |
| --- | --- | --- |
| collapse `predict`'s two stages into one (correct source) | `modeled_programs` FAILS | two-stage model is **load-bearing** |
| delete shrinker pass 1 (frame deletion) | both shrinker tests fail | load-bearing |
| delete shrinker pass 2 (payload truncation) | both shrinker tests fail | load-bearing |
| delete the every-event-KIND comparison in inertness, re-plant RED-F | still CAUGHT by the typed-StateViolation assertion | **REDUNDANT** for RED-F; kept as a stronger contract, but no reading rests on it |
| delete the write differential from `close_eof_modeled_schedules`, re-plant RED-D | still CAUGHT by the isolated echo assertion | individually redundant |
| delete BOTH write witnesses, re-plant RED-D | the whole 23,000-case campaign **PASSES** | the pair is **jointly load-bearing**; each alone is not evidence |

That last pair is exactly the shape `internal/fuzzpin/check.go` warns about in
its own deletion-attack note — a check whose only witness is another check's
finding. Both are kept and the dependency is recorded in source rather than
discovered later.

## Findings the campaigns made about the system (no shipped source changed)

1. **`handle_bytes` is two-stage, and the chunk boundary is observable.**
   TRANSLATE decodes every span in a chunk before any frame is processed, so a
   translate-stage rejection anywhere in the chunk means the chunk emits
   **nothing at all**, including for the frames before it. PROCESS then walks
   the decoded frames, so a process-stage rejection leaves the earlier frames'
   events queued. My first fragment model had one stage; the campaign refused it
   at case 16 (an oversized ping seven frames in, whose whole chunk vanished).
   The model was wrong and the core was right. Consequence recorded in source:
   rechunk invariance does not hold across a translate-stage rejection, which is
   why that family runs over legal programs only and says so.
2. **`CONTROL_PAYLOAD_LIMIT` is dead at its length site**, as above.
3. Two earlier findings from this branch stand unchanged: the PLUS_SAFE budget
   refusal racing the Java-faithful parse rejection under rechunking
   (`handshake_fuzz.rs`), and the two owner-driver oracle bugs the driver
   campaign caught in its own boundary (`driver_schedule_fuzz.rs`), including
   that "a refused write progress moves nothing" is FALSE as an invariant
   because a poll is an owner turn whatever its input carries.

## Manifest

All seven targets carry, re-derived from the tree by the checker rather than
asserted: real `#[test]` entrypoints; the declared case count present VERBATIM
as the loop literal; the generator seed present verbatim; a recomputed corpus
digest where a corpus exists; a `wall_clock` liveness guard (F005); a
crash/timeout/OOM policy; an artifact directory that exists and holds captured
runs; and a replay command that was actually run. `-campaign` executed all seven
twice each; every one REPRODUCED with byte-identical normalized outcomes.

Three targets declare an **empty corpus on purpose** —
`owner-driver-command-byte-schedules`, `fragment-control-sequences`,
`close-eof` — because none of them opens a file. `rust/ws-driver/fuzz-seeds/us017`
exists but is the US-017 minimizer's byte-for-byte expected OUTPUT, not seeds
fed to a generator; `us014`/`us015`/`us016` remain pinned by the frame-decode
target, whose corpus really is the whole `fuzz-seeds` tree and which really does
read it. Declaring a digest over files a campaign never opens would be the
existence-standing-in-for-identity defect the manifest exists to stop, so the
field says so instead.

`claim.ac2_met` and `claim.ac3_met` stay **false**. The checker raises
`UNAVAILABLE_REPRESENTED_AS_SUCCESS` for a true claim while a BLOCK stands, and
one stands. `honest_state` carries the distinction in prose: what AC2 asks for
is present; what AC3's engine vocabulary asks for is absent and was out of scope
to install.

## What I did NOT do

- **I did not install a coverage-guided engine, and did not weaken the engine
  block.** Everything here is deterministic bounded generation from fixed
  committed seeds: no coverage feedback, no corpus evolution, no engine-produced
  minimized crash artifact. AC3's vocabulary is not satisfied and the manifest
  says so.
- **I did not touch `cmd/fuzzpinctl` or `internal/fuzzpin`.** Not one line. The
  targets were fitted to the checker, never the reverse.
- **I did not change any shipped `rust/*/src` file.** Every RED plant was
  reverted from a byte-for-byte backup and `git status` was verified clean
  before continuing.
- **I did not weaken an existing test.** Two clippy fixes
  (`cloned_ref_to_slice_refs`) and a `cargo fmt --all` pass touched
  `handshake_fuzz.rs` and `driver_schedule_fuzz.rs`; both were failing the
  `fmt-check` and `clippy` legs of `make -C rust gates` on this branch before
  those fixes, and neither changed an assertion.
- **I did not make the driver target read `us017`.** Turning those minimizer
  expectations into seed material would be a real improvement and is the obvious
  next step; I declared the corpus empty and said why rather than pinning a
  digest over files nobody opens.
- **I did not run the owner gates.** No AWS, no benchmarks, no Autobahn.
- **I did not run the full `make -C rust gates` or `go test ./...`.** Restart
  pressure made small targeted runs the right trade; `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets --all-features -D warnings`,
  `cmd/fixtureguardctl -max-waivers 0`, `go test ./internal/fuzzpin/`, and every
  affected `cargo test -p <crate> --test <target>` were all run and are green.
  The `test` and `test-release` legs of `gates` over the whole workspace were
  not.
- **I did not merge or push to mainline.** Everything is on
  `claude/us021-missing-targets`.

## Claim grade

Bounded, on every target. A campaign that found nothing is evidence about the
inputs it drew and about nothing else. Six defects were planted and five were
caught; one was not, and the reason it could not be is stated. Bounded evidence,
never proof.
