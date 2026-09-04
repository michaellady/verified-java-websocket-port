# Adversarial round 3 — ledger-gates, oracle-hierarchy-gates, ac1-gates, the Rust gates, and fixture-guard's residual

STATUS: COMPLETE for what it claims. Every exit code below was read from the
process that produced it, never from a log line saying PASS. Where an anchor
failed to match I say so and score the attempt as a NON-RESULT rather than as
a survivor.

Base: mainline `6c85677`, worked in an isolated worktree `/home/user/vjwp-attack3`
on branch `claude/gate-attack-round-3` with `.quarantine` symlinked in. The brief
was the gates the first two rounds did not reach, under the question both earlier
rounds converged on:

> Does the check RE-DERIVE its claim, or does it verify that a DECLARATION is
> well formed?

**Twelve attacks got a bad tree past a gate at exit 0.** Seven are on `ac1-gates`,
two on `ledger-gates`, two on `fixture-guard`'s residual and one on the Rust
`test` and `test-release` targets. Eleven are now closed with a fix and with a
test that fails when that fix is removed. **Two mechanisms held under attack and
I say below exactly what I did to establish that.** Three residues are owner
actions because closing them moves or creates a denominator.

## Scoreboard

| # | gate | attack | before | after |
|---|---|---|---|---|
| A1 | ac1-gates forbid-unsafe | `unsafe` in a `tests/` crate root | exit 0, census identical | exit 1 |
| A2 | ac1-gates forbid-unsafe | `unsafe` in a `build.rs` that runs at build time | exit 0, census identical | exit 1 |
| A3 | ac1-gates license | a PROPRIETARY licence saying it is NOT Apache-2.0 | exit 0, census identical | exit 1 |
| A4 | ac1-gates lockfile | `git rm --cached rust/Cargo.lock` | exit 0, census identical | exit 1 |
| A5 | ac1-gates lockfile | edit the lockfile and `git add` it | exit 0, census identical | exit 1 |
| A6 | ac1-gates canaries | bad canary's lint replaced by a compile error | exit 0, census identical | exit 1 |
| A7 | ac1-gates ×3 | a vendored path dependency from outside the workspace | exit 0 on three gates | exit 1 |
| L1 | ledger-gates | ledger `status` flipped to `READY` | exit 0, five census lines identical | exit 1 |
| L2 | ledger-gates | `accepted_root_digest` rewritten to zeroes | exit 0, census identical | exit 1 |
| R1 | test, test-release | a failing test marked `#[ignore]` | exit 0 | exit 1 |
| FR2 | fixture-guard | fixture under `#[cfg(all(test, not(miri)))]` | exit 0, census identical | exit 1 |
| FR3 | fixture-guard | fixture under `#[cfg( test )]` | exit 0, census identical | exit 1 |
| FP1 | ledger-gates | rewrite a sealed record and regenerate everything | exit 1 | held |
| O3 | oracle-hierarchy | flip a rank-one reading, do not regenerate | exit 1 | held |
| O3b | oracle-hierarchy | flip a rank-one reading AND regenerate | exit 0, count moved | OWNER ACTION |
| FR1 | fixture-guard | round 2's named residual, `#[cfg(test)] use …;` | exit 1 | not a defect |

Every "census identical" cell above is a byte comparison against the baseline
line quoted in §7, not an impression.

---

## 1. ac1-gates — seven ways past, and one of them past three members at once

Round 2 read four of these members and attacked none, and said so. Attacking
them was mostly a matter of asking, for each, what the check would accept.

### 1a. forbid-unsafe scans lib and bin roots only (A1, A2)

`gateForbidUnsafe` collects `target.Kind == "lib" || "bin"` over workspace
members. `cargo metadata` on this workspace reports `{lib: 5, bin: 5, test: 32}`.
So no crate root of kind `test` is in the scan surface, and neither is a
`custom-build` script, a bench or an example.

Appending this to `rust/ws-core/tests/messages.rs`:

```rust
let value: u32 = 0xDEAD_BEEF;
let raw = &value as *const u32;
let read_back = unsafe { std::ptr::read(raw) };
```

`cargo check --workspace --all-targets --locked` exit **0** — it is a mutant and
not a non-mutant — and:

```
gate=forbid-unsafe verdict=PASS detail="10 first-party crate roots (lib+bin) all carry #![forbid(unsafe_code)]"
ac1-gates verdict=PASS gates_passed=1/1
EXIT=0
```

byte-identical to the clean tree. A2 is the same unsafe in a new
`rust/ws-core/build.rs`, which is worse in kind: a build script executes on
every machine that builds this workspace. It added a `custom-build` target,
compiled, and produced the same line at exit 0.

**A correction to round 2, which measured this surface with the wrong
instrument.** Round 2 recorded "There are 32 such crate roots across four
crates and 9 carry `#![forbid(unsafe_code)]`, so 23 are outside the scan
surface", confirmed by `grep -l`. The tokenizer-grade `hasForbidUnsafe` — the
function that exists to reject exactly this — says **7**. `grep -l` counted a
doc comment in `rust/ws-core/tests/scaffold_smoke.rs` and a string literal in
`rust/ws-oracle-harness/tests/protocol.rs`, neither of which is an attribute.
The gate's own step now prints the derived numbers:
`step=ungoverned-scan roots=32 with_attribute=7 unguarded=25 unsafe_found=0`.
The second half of round 2's sentence is also wrong in a way the number hides:
**all 32 are outside the scan surface**, not 23. The 7 that carry the attribute
are not scanned either; they simply chose to be safe. I have not edited round
2's record — the convention this repository records in `cmd/recordguardctl/prose.go`
is SUPERSEDE, do not edit — and raised `OA-round2-forbid-count` instead.

**Fix.** Every ungoverned first-party crate root — member `test`/`bench`/
`example`/`custom-build` targets, plus every target of a non-member package
whose manifest lives inside the repository — is scanned for the `unsafe`
KEYWORD, tokenizer-grade, skipping comments and string/raw-string literals and
requiring word boundaries so `unsafe_code` inside `#![forbid(unsafe_code)]` is
not a hit. A root that carries the attribute itself is exempt, because the
compiler is then enforcing it. **The printed `10` is deliberately untouched.**
Requiring the ATTRIBUTE on all 42 roots would move that count and needs it added
to 25 files, which is `OA-forbid-unsafe-scan-surface` and not mine.

### 1b. license verified two substrings (A3)

`licenseFileLooksApache2` was `Contains("Apache License") && Contains("Version 2.0")`.
I replaced the 201-line canonical LICENSE with eight lines:

```
                        PROPRIETARY SOFTWARE LICENSE
                              All Rights Reserved

   This software is NOT distributed under the Apache License,
   Version 2.0, or under any other open-source licence.
```

```
gate=license verdict=PASS detail="root LICENSE is Apache-2.0 and all 5 members declare license=Apache-2.0"
EXIT=0
```

The gate printed a sentence the file it had just read contradicts in words.

**Fix.** `licenseIdentityProblem` re-derives the file's IDENTITY: SHA-256 over
the whole document against the canonical Apache-2.0 digest
`c71d239d…`, which is what the committed LICENSE carries. When the digest
differs, the ordered fourteen-clause skeleton (`TERMS AND CONDITIONS…` through
`APPENDIX: How to apply…`) is walked to say WHERE the document stops being
Apache-2.0, so a truncated licence gets a diagnostic and not just a mismatch.

### 1c. lockfile compared the worktree to the index (A4, A5)

The step was `git diff --exit-code -- rust/Cargo.lock`. `git diff` with no
commit argument compares the working tree to the INDEX. Two consequences:

- `git rm --cached rust/Cargo.lock` leaves the file untracked. An untracked path
  has no diff. The "reproducible lockfile" gate reported
  `Cargo.lock byte-identical and git-clean` at exit **0** with **no committed
  lockfile in the repository at all**.
- Appending a line and running `git add` gives `git diff HEAD --stat` of
  `1 file changed, 2 insertions(+)` and `git diff` of nothing. Exit **0**, same
  sentence. Every real change stages before it commits.

**Fix.** Two steps: `git ls-files --error-unmatch -- rust/Cargo.lock` asserts the
path is tracked, then `git diff --exit-code HEAD -- rust/Cargo.lock`.

### 1d. the canary read an exit code, not a detection (A6)

`evaluateCanaryPolarity` required `bad.clippyExit != 0`. I replaced
bad-scaffold's `if flag == true { true } else { false }` with a call to an
undefined function. Clippy's output then contains **zero** occurrences of
`clippy::`; it is rustc E0425. The gate:

```
gate=canaries step=bad-scaffold:forbid-scan roots=1 violations=1 exit=1
gate=canaries step=bad-scaffold:clippy cmd="cargo clippy --all-targets -- -D warnings" exit=101
gate=canaries verdict=PASS detail="polarity proven: … bad-scaffold failed scan and clippy as required (exits 1/101)"
EXIT=0
```

`exits 1/101` is the same pair the honest run prints. The claim the canary makes
is that the LINT gate can detect a violation; a nonzero exit is the declaration
that something failed.

**Fix.** The polarity is re-derived from the DIFFERENCE. The bad canary must
COMPILE (`cargo check --all-targets` exit 0, so the refusal is attributable to
the lint and not to a broken crate) and clippy must NAME at least one
`clippy::<lint>`, counted out of clippy's own output. Both halves fire
independently, so neither can be deleted behind the other.

### 1e. "external dependency" meant "cargo wrote a source field" (A7)

`externalDependencies` returned packages with a non-empty cargo `source`. That
field is a label cargo writes for registry and git dependencies and leaves NULL
for path dependencies. So I vendored a crate at `third_party/attackdep/` —
`license = "Proprietary"`, no forbid attribute, an `unsafe { *bytes.as_ptr() }` —
and added `attackdep = { path = "../../third_party/attackdep" }` to
`rust/ws-core/Cargo.toml`. Because it lives OUTSIDE the workspace directory it
does not become a workspace member. `cargo metadata` reports
`source: None, is_workspace_member: False`. It compiles into ws-core, the core
library. Three gates, each at exit **0** and each byte-identical to the clean
tree:

```
gate=forbid-unsafe verdict=PASS detail="10 first-party crate roots (lib+bin) all carry #![forbid(unsafe_code)]"
gate=dependency-inventory externals=0 inventory_entries=0 …
gate=dependency-inventory verdict=PASS detail="workspace has 0 non-path dependencies; inventory agrees (0 entries)"
gate=audit audit_surface: 0 non-path dependencies
gate=audit verdict=PASS detail="zero non-path dependencies (empty audit surface); …"
```

The `license` gate is a fourth: it reports `all 5 members declare license=Apache-2.0`,
which stays true while a Proprietary crate is linked in, because it reads
members.

The one member that noticed is `lockfile`, and only because Cargo.lock had not
been committed yet: `gate=lockfile verdict=FAIL detail="rust/Cargo.lock differs
from the committed lockfile"`. A change that commits its lockfile — every real
one — passes that step legitimately. So the tripwire is a review of the diff,
not a gate.

**Fix.** External means **not a workspace member**. That covers registry, git
and path-outside-the-workspace alike, and a path dependency's source is reported
as its resolved directory rather than as the empty string. On the clean tree
there are no non-member packages, so `externals=0 inventory_entries=0` does not
move.

### 1f. the below-MSRV differential vanished in the one case it could run

`gateMSRV` computes `olderAvailable` and, when it is FALSE, prints a `pending=`
note. When it is TRUE the differential is neither executed nor noted. On this
host `stable` resolves to `rustc 1.94.1` against an MSRV of `1.95.0`, so
`olderAvailable` is true and the baseline output carries no `gate=msrv pending=`
line at all. The tool's own header says checks outside its claim are "recorded
as explicit `pending=` notes, never silently passed". Both branches now print.
Whether it should EXECUTE is `OA-below-msrv-differential`: a below-MSRV build
that SUCCEEDED would be a finding about the declaration, not a failure of the
gate, so running it is a decision rather than a fix.

### 1g. what ac1-gates did NOT lose

- **`hasForbidUnsafe` is a real tokenizer and I did not get past it.** I tried
  the attribute inside a line comment, inside a nested block comment, inside a
  string literal and inside a raw string, and after the first item; each is
  correctly refused. The prelude walk handles shebangs, nested `/* */` per Rust,
  and `]` inside a literal. It is the strongest single function in this tool and
  it is why A1's correct measurement is 7 rather than `grep -l`'s 9.
- **`memberInheritsWorkspaceKey` is section-aware.** The same key under
  `[package.metadata.*]` is a decoy and does not satisfy MSRV or license
  inheritance.
- **The MSRV declaration triple cannot be lowered cheaply.** `channel`,
  `[workspace.package] rust-version` and the intake pin must agree AND a
  version-named toolchain matching the MSRV must be installed, or
  `buildUnderMSRVOutcome` FAILS rather than passing pending. The only installed
  toolchains are `1.95.0` and a symbolic `stable`, so lowering the triple to
  1.94.1 fails for want of a `1.94.1-…` toolchain.
- **The audit gate fails closed.** With any non-member dependency present and no
  audit tool installed it returns a failure, not a pending note. Its empty-surface
  pass is honest about being an empty surface.

---

## 2. ledger-gates — the regeneration copied two fields from the file it verifies

`deltaledgerctl --check` regenerates the ledger document from the Go definitions
and compares bytes. `BuildLedgerFileFrom` does `built := existing` and then
overwrites `$schema`, `schema_version`, `head`, `records`, `supersessions`,
`unledgered_disagreements` and `records_without_mismatch_class`. **Seven fields
are not overwritten**, so they are compared to themselves and can never fail
that comparison:

```
evidence_kind  normative_authority  append_implementation
production     publication          accepted_root_digest  status
```

Five of the seven are pinned to `const` values by
`schemas/behavior-delta-ledger-1.2.0.schema.json`, and
`VerifyEvidenceDocumentSchemas` really does check it — flipping `production` to
`true` gives `at '/production': value must be false`, exit 1. That is a control,
run, and it is why the enumeration below is two rather than seven.

The other two are free.

**L1 — `status`.** The schema admits `READY` or `BLOCKED_PENDING_BASELINE`.
Rewriting `BLOCKED_PENDING_BASELINE` to `READY`:

```
ok: evidence/java/behavior-delta-ledger.json equals the regeneration (59 records, head sha256:f10dd526…, document schema 1.2.0)
ok: evidence/java/ledger-supersessions.json equals the chain's supersession map (6 link(s), …)
ok: ledger integrity verified (frozen prefix through sequence 35, …, unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
ok: evidence/java/legacy-record-adjudications.json adjudicates records 1-49, … (records_without_ac3_class recomputed = 0 of 59)
ok: evidence/governance/owner-decision-digests.json equals the derivation and 7 governance record digest(s) recomputed from the protected store and matched
EXIT=0
```

All five lines byte-identical to the clean tree. This one is not cosmetic:
`internal/formalplan/concurrency.go:546` reads the field and only DEMANDS that
the plan record the append as blocked *while the ledger says it is blocked*, so
the ledger's self-declaration switches a downstream check off.

**L2 — `accepted_root_digest`.** The schema constrains it to the SHAPE of a
digest. Rewriting it to sixty-four zeroes exits **0** with the census unmoved,
while eight sibling documents under `evidence/java/` and two schemas carry the
real accepted root as a `const`.

**Fix — `internal/deltaledger/envelope.go`, wired into `VerifyIntegrity`.**
`accepted_root_digest` must equal the root the other committed documents under
`evidence/java/` agree on, with the ledger excluded so it can never be its own
authority; disagreeing siblings are a refusal rather than a majority vote, and
a tree where nothing carries a root is a refusal rather than a vacuous pass.
`status` must be `BLOCKED_PENDING_BASELINE` unless
`evidence/java/autobahn-baseline.json` is `PASS` — the rule the build comment
already stated in prose and nothing executed. Neither derivation adds a
constant. The gate's summary line now names the rule, because a rule that runs
unnamed is the silence this package was rebuilt to remove.

### 2a. the frozen prefix HELD, and here is what I did to establish it

`recordDigest` hashes `{schema_version, sequence, previous_digest, delta}` and
`previous_digest` is the prior record's digest, so the chain is genuinely
hash-linked and pinning sequence 35 does pin every byte before it. That is a
reading; the attack is what settles it. I changed one substring inside a record
sealed at sequence 10 — a Java line reference, `Draft_6455.java:262-286` to
`:262-999` — which is the shape of an edit someone would make while "tidying".
Comparing without regenerating fails on the byte comparison, so I regenerated
every artifact first and only then ran `--check`, which is the attack that
matters:

```
[frozen-prefix] THE FROZEN LEDGER PREFIX CHANGED. Sequence 35 now digests to sha256:62190564…,
  but the owner ruling … requires the prefix through sequence 35 to remain byte-identical at sha256:3fcd461c…
[legacy-record-adjudications] legacy-record adjudications (61 problem(s)):
  pre_vocabulary_head is sha256:eaa6eac8… but the record at sequence 49 digests to sha256:581fcf84…
  sequence 10: the entry binds record_digest sha256:5a0bcec7…; the record digests to sha256:33d2d2d5…
  …
EXIT=1
```

Three independent refusals, and `unledgered_disagreements = 5` on the write
path besides, because the committed observation set outlived the definition
change exactly as designed. **This is a re-derive mechanism and it held.**

### 2b. what the ledger gate does not see

The rank-one probe in §3 edits `evidence/us005-public-rfc-divergence-census.json`.
`ledger-gates` names `census evidence and ledger binding` among its rules and
exits **0** over that edit, so the binding does not cover
`rfc_strict_expectation`. That is a scope statement, not a defect claim: I did
not establish that it ought to.

---

## 3. oracle-hierarchy-gates — the mechanism is honest and its census is anchored to nothing

Round 2 tried two schema probes, both refused before adjudication ran, and said
plainly it had barely tried. I went at the evidence instead.

The design is sound where it counts. `VerifyRules` recomputes the exhibited
overrides from the census families and compares them to the committed register
**in both directions** — an exhibited override the register does not enrol is a
failure, and an enrolled entry the evidence does not exhibit is "the register is
not a waiver list". The register is never an input to its own recomputation.
`CheckFamilyRules` also refuses a rank declared and then silent, a rank declared
ABSENT that votes, and an override in the pure rank-four-against-rank-five
family where no oracle above rank four speaks. The rank-one binding hashes its
artifacts on every run and states in its own text what it is NOT bound to (the
RFC text itself, which no file here carries) together with the owner action that
would change that. I found nothing dishonest in it.

**O3 — the probe.** `us005.pub.0005` is an enrolled override where rank one
governs with `closed` against a Java/Rust agreement of `open`. I flipped that
one `rfc_strict_expectation` to `open` — a higher oracle quietly made to agree
with the pair AC2 says cannot settle a question on its own. My first two attempts
to land this edit **did not match their anchor** (the sentence is stored with a
`—` escape, and the third form was ambiguous across 18 entries); both are
NON-RESULTS and I verified the file was byte-unchanged before reporting anything
about them. The third landed, asserted by re-reading the parsed JSON and
checking exactly one entry had moved.

Un-regenerated, the gate refuses:

```
oraclerankctl: evidence/oracle-hierarchy/adjudication-register.json does not equal
  its recomputation from the evidence (committed 92469 bytes, recomputed 87101 bytes)
EXIT=1
```

Regenerated — which is what the author of such an edit does — it passes:

```
oraclerankctl: wrote … (87101 bytes); 640 propositions, 589 Java/Rust agreements, 38 overridden by a higher oracle
oraclerankctl: 640 propositions adjudicated; 589 Java/Rust agreements, 38 of them overridden by a higher oracle and every one enrolled
EXIT=0
```

So the gate is exactly as strong as the tripwire on its printed numbers, and
**nothing asserts 640, 589 or 39.** This is round 2's "census number that nobody
asserts" in its third gate, after `nodes=29` and `files=49 loops=310`. I am NOT
fixing it: binding those three needs an anchor outside the gate and creates a
denominator the gate is then measured against, which is precisely the ruling
round 2 recorded for `nodes=29`. `OA-oracle-census-anchor`.

**How hard I actually tried, since that paragraph was the most useful one in
round 2's record.** I read `adjudicate.go`, `document.go`, `neutralcheck.go` and
the family list in `census.go`, and I ran one evidence-level probe in both its
polarities. I did **not** attack: the join-degeneracy analysis, the collision
analysis, the independence probe's ten entries, the neutral derivation in
`internal/rfcneutral` (whose claim to ignore recorded expectations rests on a
test that `oracle-hierarchy-gates` does not run — `go-suite` does), the Autobahn
family's 488 rank-two-governed propositions, or the `Strength` and `basis`
prose round 2 named. Two rounds have now failed to break this gate and neither
has attacked its arithmetic.

---

## 4. The Rust gates — a failing test that is never run

`fmt-check`, `clippy`, `test` and `test-release` were untouched by both earlier
rounds. Each is a bare cargo command in the Makefile whose exit code is the whole
verdict, and libtest exits 0 over a test it skipped. Appending to
`rust/ws-core/tests/messages.rs`:

```rust
#[test]
#[ignore]
fn attack_r1_this_assertion_is_false() {
    assert_eq!(1, 2, "ATTACK R1: this test fails whenever it is run");
}
```

Run detached, exit codes read from files in my own worktree:

```
cargo fmt --all -- --check                                          FMT_RC=0
cargo clippy --workspace --all-targets --all-features -- -D warnings CLIPPY_RC=0
cargo test --workspace --all-targets --all-features                 TEST_RC=0
```

The only trace is line 371 of a 41KB log — `test attack_r1_this_assertion_is_false … ignored` —
and a workspace-wide tally of `1 ignored`, which nothing parses. This is round
1's B2/B3 (a failing test behind a build tag passing go-suite) in Rust dress.
go-suite was fixed for it in round 1 and these were not, which is round 2's
"a defect class does not stay fixed where it was found", now with three
instances.

**Fix.** `-- --include-ignored` on both targets. There are **zero** `#[ignore]`
attributes under `rust/` today, so this changes which tests run not at all, and
turns a fact that happens to hold into one the gate enforces by construction. I
verified `--include-ignored` survives the doctest harness that `test-release`
reaches (`cargo test -p ws-core --release --doc -- --include-ignored`, exit 0)
before wiring it in, because a flag the doctest runner rejected would have
turned a 50-minute chain red at its last step.

I did not defeat `fmt-check` or `clippy` on their own terms and I did not try
hard: I ran them against the mutant above and read their exits. Neither has been
attacked by anyone.

---

## 5. fixture-guard's residual — narrower than round 2 thought, and worse next door

Round 2 named one residual it did not close: a `#[cfg(test)]` on something other
than a module, where `nextBrace` adopts an unrelated body.

**FR1 — the named residual is not a defect for missed violations.** I built the
file: `#[cfg(test)] use std::vec::Vec;`, a production function, then a real
`#[cfg(test)] mod tests` holding a count-shaped guard. The gate found it, exit
**1**, `files=50 loops=311 violations=2`. The mis-adopted region is followed by a
correct one, because `cfgTestRegions` resumes scanning at the adopted region's
end and the real attribute is after it. A region wrongly adopted can only be a
SUPERSET of what follows it or be followed by the right one; it cannot hide a
later fixture. Round 2 was right that the shape is wrong and wrong that it lets a
violation through. Its other effect — production code scanned as a fixture —
is real and unchanged.

**FR2, FR3 — the needle is one byte string, and its failure is silent.** The
scan was `strings.Index(masked, "#[cfg(test)]")`. Two files in
`rust/ws-core/src/`, each carrying the same count-shaped guard round 2's control
uses:

```rust
#[cfg(all(test, not(miri)))]   mod tests { … assert!(polls < 4096, …) … }
#[cfg( test )]                 mod tests { … assert!(polls < 4096, …) … }
```

```
gate=fixture-liveness-guard step=scan files=49 loops=310 violations=0 waivers=0 max_waivers=0 budget_waivers=0 max_budget_waivers=0 unscanned=0
gate=fixture-liveness-guard result=PASS
EXIT=0
```

**Byte-identical to the clean tree, including `unscanned=0`.** This is worse than
the H2 case round 2 closed: there, the needle matched and only the body was
unreachable, so a gap was reported. Here the needle never matched, and the gap
list is keyed on the needle, so the mechanism built to make a skip loud had
nothing to be loud about — and `if len(regions) == 0 { return nil }` in the
caller dropped both files before `res.files++`.

**Fix.** The attribute is recognised by what it MEANS: any `#[cfg(…)]` whose
predicate names the bare identifier `test`, with string literals stripped first
so `feature = "test"` does not count, and `not(test)` excluded by name. Stated
ceiling rather than a guard: `#[cfg_attr(test, …)]` is not recognised, and a
predicate mixing `not(test)` with a live `test` arm would be excluded. All 16
cfg-test attributes under `rust/` today are the plain spelling on a `mod` line,
so neither edge is exercised and the region set is identical.

---

## 6. Fixes, and both directions for each

Every fix was shown to work twice: the attack replayed against the fixed gate
and refused with the finding quoted, and the unmodified tree still passing with
its census quoted. On top of that, each carries a **deletion attack** — a
mutation that COMPILES, applied by an anchor whose match is asserted rather than
eyeballed, with the suite required to go red.

```
D1  license identity always accepts                     CAUGHT
D2  unsafe token scan finds nothing                     CAUGHT
D3  external = non-path (the pre-fix definition)        CAUGHT
D4  canary no longer requires the bad crate to compile  CAUGHT
D5  canary no longer requires a named clippy lint       CAUGHT
D6  attribute recognised by one spelling again          CAUGHT
D7  not(test) no longer excluded                        CAUGHT
D8b identifier boundary dropped                         CAUGHT
D9  envelope status check disabled                      CAUGHT
D10 envelope accepted-root check disabled               CAUGHT
D11 status pinned to a constant instead of derived      CAUGHT
D12b unbound envelope passes vacuously                  CAUGHT
D13 the envelope rule is not called by the gate         CAUGHT
```

Two of those did not start out that way and both are recorded rather than
tidied. **D8** was a NON-MUTANT: removing the word-boundary test left `isWord`
unused and Go refused to compile it, which proves nothing, so it was rewritten
as D8b (`… || !isWord(x) || isWord(x)`) and then caught. **D12 SURVIVED** on its
first run: with the unbound-tree refusal removed, `AcceptedRootFromSiblings`
fell through and returned the empty string, and the accepted-root comparison
failed anyway — so my test saw red for the wrong reason and could not tell the
two apart. The test now asserts the REFUSAL TEXT ("bound to nothing") on a tree
where the baseline is present and no sibling carries a root, which is the only
shape that separates "unbound" from "mismatched", and D12b is caught. A survivor
that is really a weak test is the thing this discipline exists to surface.

---

## 7. The chain

Baselines before any change, each read from the process:

```
gate=forbid-unsafe verdict=PASS detail="10 first-party crate roots (lib+bin) all carry #![forbid(unsafe_code)]"
gate=dependency-inventory externals=0 inventory_entries=0 inventory=rust/gates/dependency-unsafe-inventory.json
gate=license verdict=PASS detail="root LICENSE is Apache-2.0 and all 5 members declare license=Apache-2.0"
gate=lockfile verdict=PASS detail="cargo build --locked and cargo metadata --locked succeeded; Cargo.lock byte-identical and git-clean"
gate=canaries verdict=PASS detail="polarity proven: … (exits 1/101)"
ac1-gates verdict=PASS gates_passed=8/8
gate=fixture-liveness-guard step=scan files=49 loops=310 violations=0 waivers=0 max_waivers=0 budget_waivers=0 max_budget_waivers=0 unscanned=0
oraclerankctl: 640 propositions adjudicated; 589 Java/Rust agreements, 39 of them overridden by a higher oracle
```

CHAIN-CENSUS-PLACEHOLDER

---

## 8. What I did NOT attack, and what I could not defeat

- **No owner gates.** No AWS run, no benchmark, no Autobahn run, no
  `internal/lab` execution path. No label was added to any pull request.
- **Nothing from rounds 1 and 2 was re-attacked**: `record-guard`, `go-suite`,
  `pin-guard`, `plan-guard`, and `fixture-guard`'s A/B/C shape detectors,
  polarity self-check, waiver ceiling and `budget.go` anchors. `adapter-linkage`
  and `protocol_branch.go` were left alone as round 2 left them.
- **`ledger-gates` rules I did not attack**: observation provenance, the
  handshake mapping census, the protocol-rejection class, the supersession
  rules, `VerifyAdjudication`, the held proposal drafts, the corpora
  re-derivation and the live-mapping source binding. I attacked the frozen
  prefix, the legacy-record adjudications (as collateral of the same probe), the
  document-schema rule and the envelope. `VerifyGovernance` I left to round 2's
  hard stop, which the Makefile has since disclosed correctly.
- **`oracle-hierarchy-gates`**: see §3 for exactly how far I got, which is one
  evidence probe in two polarities and a reading of four files.
- **`fmt-check` and `clippy`** were run, not attacked.
- **The `unsafe_usage` prose in the dependency inventory remains unvalidated**,
  and round 2 was right to call it round 1's B5 unattacked. I could not attack it
  and I should say why rather than leave it as a reading: the inventory has
  **zero** entries because the workspace has zero non-member dependencies, and
  creating one that cargo will resolve needs either network egress to a registry
  or the vendored path dependency of A7 — which, after A7's fix, is refused
  before any `unsafe_usage` string is read. So the field is unreachable from
  here. A reviewed entry claiming "no unsafe" for a crate full of it would still
  pass, and nothing in this repository can currently demonstrate that.
- **I did not perturb `.quarantine`** in any way; staging that symlink is F011.
- **I did not add, remove or renumber any node the plan already had.** I moved
  one node to `done` and added four owner actions.

---

## 9. Owner actions this round raises

- **`OA-forbid-unsafe-scan-surface`** — should the 32 first-party crate roots of
  kind `test` be required to carry `#![forbid(unsafe_code)]`? Both measurements
  are in the plan: 32 roots, 7 with the attribute, 25 without, and the printed
  count moves from 10 to 42 if the answer is yes. Reported, not taken.
- **`OA-oracle-census-anchor`** — should anything bind `640 propositions;
  589 agreements; 39 overridden`? Binding them creates a denominator.
- **`OA-below-msrv-differential`** — should the differential execute where an
  older toolchain exists?
- **`OA-round2-forbid-count`** — how to correct `9` to `7` in a landed record,
  given the SUPERSEDE-do-not-edit convention.

---

## 10. Process

Isolated worktree throughout, `.quarantine` symlinked and never staged. **No
`pkill` was used and no process of mine was killed**; the one long Rust run was
detached and wrote its exit code to a file inside my own worktree, never to the
shared scratchpad. `df -h /` was read before starting and before diagnosing
anything: 8.7G free at the start, 8.6G during the Rust run, so no timing or
failure here is a disk reading. Every mutation was applied by an anchored edit
that asserted its own uniqueness and then echoed the changed line back and
asserted it had changed; the two anchor failures in §3 are reported as
NON-RESULTS. Every mutant was compiled before being scored, and the one that did
not compile (D8) is recorded as a non-mutant rather than as a survivor. Reverts
were verified with `git status --porcelain` and, for the oracle probe, with
`cmp` against a saved copy.

## 11. The shape, three rounds on

Round 1: an exemption should be re-derived, not re-read. Round 2: evidence must
be falsifiable, not merely checkable. Round 3 adds the narrowest of the three,
and it is the one that produced the most findings here:

**A check inherits its answer whenever the thing it verifies is also one of its
inputs.** The ledger's regeneration copied `status` and `accepted_root_digest`
from the document it was about to compare against. `git diff` was asked about the
index, which the attacker writes. The canary asked for an exit code, which any
failure supplies. `licenseFileLooksApache2` asked the licence to contain the
words it would be judged by. In each case the check ran, re-derived something,
and re-derived the wrong thing — a value that moves with the attack instead of
against it.

And the three older patterns all recurred, none of them fixed by having been
named:

- **The census number that nobody asserts**, now at `640/589/39` and at
  `files=49 loops=310`, joining `nodes=29`. Every silent attack in this document
  is visible only as one of those moving, or not moving at all — and eight of
  the twelve moved nothing.
- **The prose that is never validated against the world**: `10 first-party crate
  roots`, `Cargo.lock byte-identical and git-clean`, `polarity proven`, and the
  ledger's own `status`.
- **A defect class does not stay fixed where it was found.** The
  ignored-test hole is round 1's build-tag hole, fixed in go-suite and shipped in
  `cargo test`. The silent-skip hole is round 2's H2, fixed for the body and
  shipped for the attribute.
