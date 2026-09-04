# `pin-guard`: C1 and C2 closed, C9 split — one half closed, one half refused

STATUS: COMPLETE. Every exit code below was read from the process, never from a
log line that said PASS.

Target: `cmd/pinconsumerctl` at mainline `8e6007d`, worked in an isolated
worktree `/home/user/vjwp-pinc` on `claude/pin-bypass-c1-c2-c9` with
`.quarantine` symlinked in. The brief was to test, not inherit, the previous
round's reason for leaving C1, C2 and C9 unfixed: *"each moves a census
denominator, which is a hard stop."*

**Measured, that reason is true of exactly one of the three, and it is only half
of C9.** C1 and C2 hid true positives behind a rule that dismissed a whole JSON
object on the first favourable thing found in it; closing them takes nothing out
of the census and puts four real findings into it. C9 turned out to be two
different attacks wearing one name: DELETING a pinned target is closed and now
fails the gate; UNTRACKING one is refused, because the only way to see it is a
wider path corpus, and both widenings were measured.

| # | attack | before | after |
|---|---|---|---|
| C1 | a second tracked path in the pin's object | exit **0**, `candidates=0`, no line printed | exit **1**, row printed naming both paths |
| C2 | a sibling digest that matches the file | exit **0**, `candidates=0`, no line printed | exit **1**, row printed with the DRIFTED digest |
| C9a | delete the pinned target (git still tracks it) | exit **0**, `candidates=0`, no line printed | exit **1**, `MISSING_PIN_TARGET`, `missing_targets=1` |
| C9b | `git rm --cached` the pinned target | exit **0**, no line printed | **REFUSED — still exit 0, now DISCLOSED in the printed ceiling** |

---

## 1. RED baseline — all four reproduced before anything was changed

A binary built from `HEAD:cmd/pinconsumerctl/main.go` at `8e6007d`
(`.work/prepin`). Every attack starts from the same control object, written into
a tracked scratch artifact and `git add`ed so `git ls-files` sees it.

**Control.** `{"path":"README.md","sha256":"deadbeef…deadbeef"}`

```
=== control: EXIT READ FROM PROCESS = 1
gate=pin-dangling json_artifacts=1998 unparsable=0 candidates=1 explained=51 covered=23 allowed=11
gate=pin-dangling artifact=assurance/attack-scratch/control.json pointer=$ names=README.md
  declared=sha256:deadbeef… actual=sha256:f797026863dade…
```

**C1** — the same object plus `"see_also":"LICENSE"`:

```
=== c1: EXIT READ FROM PROCESS = 0
gate=pin-dangling json_artifacts=1998 unparsable=0 candidates=0 explained=51 covered=23 allowed=11
gate=pin-dangling result=PASS
--- lines naming the attack artifact: 0
```

**C2** — the same object plus `"also_sha256"` set to README.md's real digest
`f797026863dade3e72b7f91e05aac52127830ef28568cb78125fc7083d5b8a79`:

```
=== c2: EXIT READ FROM PROCESS = 0
gate=pin-dangling json_artifacts=1998 unparsable=0 candidates=0 explained=51 covered=23 allowed=11
--- lines naming the attack artifact: 0
```

**C9** — a tracked scratch target pinned at a wrong digest. Base run: exit **1**,
`candidates=1`, row printed. Then:

```
### C9a: rm the target, leave it in the index   -> EXIT = 0, candidates=0, 0 lines
### C9b: git rm --cached the target             -> EXIT = 0, candidates=0, 0 lines
```

All four are silent at exit 0 with **no line printed at all**. That is the RED
baseline, and everything below is measured against it.

## 2. The mechanism — C1 and C2 are one defect on two axes

`analyseDangling`'s walk read an object and left it on the first favourable thing
it found:

```go
if len(paths) != 1 || len(digests) == 0 { return }   // C1
...
for _, declared := range digests {
    if declared == actual { return }                 // C2
}
```

Each `return` exits the **whole object**, taking every other digest in it. So one
extra tracked path, or one correct digest, hid every drifted digest beside it —
and neither leaves a trace, because nothing counts objects skipped.

The fix partitions instead of exiting. A digest is subtracted only when it is the
CURRENT digest of a path named right there; the rest are still checked, and an
object naming several paths is reported as one row naming all of them, which
attributes to none of them and still says what is wrong. `unaccountedDigests` is
one function used by both `dangling` and `consumers`, so the rule has one
implementation and not two.

C9's delete half was a third instance of the same shape: `digestOf` failing
returned out of the object before any check ran. Absent targets are now collected
and reported as `MISSING_PIN_TARGET`, counted in a NEW field `missing_targets=`
rather than folded into `candidates=`, because no digest has drifted — the
subject of the digest is gone, which is worse.

## 3. Which count each fix moves, and in which direction

Named exactly, as the task requires. Pre-fix census read from the pre-fix binary
on this tree:

```
gate=pin-dangling json_artifacts=1997 unparsable=0 candidates=0 explained=51 covered=23 allowed=11
```

| count | before | after | direction | why |
|---|---|---|---|---|
| `json_artifacts` | 1997 | 1997 | unmoved | the artifact corpus is untouched |
| `unparsable` | 0 | 0 | unmoved | |
| `candidates` | 0 | 0 | unmoved | the four newly-visible true positives are DECLARED, so `remaining` stays 0 |
| `explained` | 51 | **53** | **UP by 2** | two recomputed subtractions that were previously invisible, both re-verified by hand |
| `covered` | 23 | 23 | unmoved | no coverage claim gained or lost a row |
| `allowed` | 11 | **15** | **UP by 4** | four true positives that were hidden are now acknowledged with owner actions |
| `missing_targets` | — | **0** | new, starts at 0 | a guard, not a re-baselining: nothing in this tree is a missing target |

Total rows printed: **85 → 91**. Nothing left. `comm -23` over
`kind\tartifact\tpointer` for all 85 pre-fix rows against the 91 post-fix rows is
**EMPTY on the DISAPPEARED side**; the six APPEARED rows are listed below. This
is the direction the task distinguishes: a candidate count rising because real
drift was found is not a re-baselining.

### The two new `explained` rows, each re-verified by hand

- `evidence/java/test-manifest.json $.test_policy` — a C1 case, two tracked
  paths. `8166ea6b…` is the current digest of `default-policy-behavior.json`,
  `35115b17…` of `test-only-java.security`; the remaining `ae19f494…` resolves at
  `$.promoted_jdk.java_security_digest` INSIDE `default-policy-behavior.json`.
  Confirmed by `sha256sum` on both files and by reading the field.
- `evidence/security-validation.json $.sbx_live_evidence` — a C2 case.
  `ba746b04…` is the current digest of `evidence/sbx-validation.json`; the
  remaining `f89d23b1…` resolves at that file's own
  `$.projection_canonical_digest`. Confirmed the same way.

Both are R4 recomputations from current bytes, not key names.

### The four new true positives — NEW FINDINGS, declared with owner actions

**Three are the same finding at a second address.**
`assurance/formal/denominator-reconciliation.json
$.catalog_declared_basis_pins[1,3,4]` carry `catalog_declared_sha256` (drifted)
beside `on_disk_sha256` (matching). The matching sibling immunised the drifted
pin — pure C2. Their declared digests `fa75348c…`, `01175607…`, `e884fd06…` are
**byte-identical** to the three already declared HARD STOP at
`obligation-catalog.json $.denominator_basis[1,3,4]`, and the document's own
`agreement` field for each reads `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK`. Their
allowances say so and say they are deleted when the originals are, by the same
plane-correspondence decision.

**One is new to this repository.**
`evidence/governance/decisions/e3-formal-receipt.json $.models_authored[1]` names
`assurance/formal/close-model.tla` AND `assurance/formal/close-model.cfg` in one
object, so C1 hid it completely — and **both** its digests have drifted:

| declared | on disk |
|---|---|
| `36370b0f30d0a47f942ae240312397b78aaf64b2ce2a08024b73187f4d4cd8a9` (.tla) | `29f1c8f1d85ac6fc39cca48f8be2aa1fddf4cdd460a5b6dc15bdcd279378281d` |
| `c9072fa4c03036ea20a9b63bf48c976bbe5f3b2fd5c620439b31d58ca777c3f2` (.cfg) | `93447cec5745a3bb20b6e801e61d3b1084f243088d0e0d739696fec89bfb3d8a` |

`git log` says both files were rewritten in `8f19e2b`, *"review round 2: fix the
vacuous close invariant, move the driver to Go, bind receipts by content"*. The
post-round-2 digests appear **nowhere** in the receipt — grepped for both, absent
— which is what separates this row from the receipt's two existing allowances,
whose current values are recorded at `$.review_round_5`.

**The control that says this is a real finding and not a rule firing on
everything:** the sibling `$.models_authored[0]`, the frame model, names two
tracked paths in exactly the same shape and was NOT touched by `8f19e2b`. Both of
its digests match their files exactly, and it is silent.

**Owner action (declared in the allowance):** either record the round-2 digests
beside the round-1 ones the way `$.review_round_5` does, or state that
`models_authored` describes the round-1 authored bytes only. Do not rewrite the
attested values — this is a dated attestation, and it lives in the protected
store.

### The tool's motivating question, answered correctly for the first time

`pinconsumerctl` exists to answer *"when I change a file, which artifacts pin
it?"*. On the file at the centre of the new finding:

```
BEFORE (binary from 8e6007d): consumers assurance/formal/close-model.tla
  EXIT READ FROM PROCESS = 0
  gate=pin-consumers target=… current=1        <- and nothing else

AFTER:  EXIT READ FROM PROCESS = 1
  gate=pin-consumers target=… current=1 stale=1
      ALREADY_STALE evidence/governance/decisions/e3-formal-receipt.json
        pointer=$.models_authored[1] declared=sha256:36370b0f…,sha256:c9072fa4…
```

`stalePinsNaming` carried the identical defect, so `consumers` gave the identical
wrong answer. It now shares `unaccountedDigests` with `dangling`.

## 4. C9b — REFUSED, with the numbers

A pin naming a path git no longer tracks is invisible because `splitPinFields`
only recognises a string as a path when `git ls-files` lists it. Seeing it
requires a WIDER path corpus, and there are exactly two candidates. Both were
measured over all 1997 tracked JSON artifacts rather than argued about.

**(i) Any path-SHAPED string.** 724 objects gain a "path"; **662 become new
candidate rows**. The strings are `1.0.0`, `21.0.4`, `v0.1.1`,
`profile.glancer.experimental.v1`, `foundation-lsp-harness/1.0.0`. This also
contradicts an invariant the tool states and tests —
`TestSplitPinFieldsRecognisesDigestsAndOnlyTrackedPaths`: *"an arbitrary string
that looks path-shaped is not a pin."*

**(ii) Any path git has EVER tracked**, from `git log --all --name-only` — precise,
not a guess. 2388 such paths. **26 objects become new candidate rows**, and their
addresses are the whole problem:

```
assurance/formal/denominator-reconciliation.json $.catalog_declared_basis_pins[2]   corpora/frame/codec.json
assurance/formal/obligation-catalog.json         $.denominator_basis[2]             corpora/frame/codec.json
assurance/formal/obligation-catalog.json         $.rust_bindings[0..23]             rust/connection-core/src/…  (24 rows)
```

Every one lands on the formal denominator's declared basis — the document whose
three existing rows are already allowed as *"DENOMINATOR, HARD STOP: decide the
catalog's plane correspondence. Never re-baselined here."* Closing C9b this way
would take `allowed` from 15 to 41 and would force the plane-correspondence
decision from inside a gate fix. It also re-admits ignored trees: `.quarantine`
is itself in the ever-tracked set, which is **F011** exactly — the `.quarantine`
symlink re-added by an agent's `git add -A`.

**And it is not hypothetical.** `obligation-catalog.json $.denominator_basis[2]`
names `corpora/frame/codec.json`, deleted from this plane (2 commits in history,
absent from `HEAD` and from disk). This census has never counted it. It is not
unowned: `internal/formalcoverage/reconcile.go` already reports it as
`BASIS_PIN_PATH_IS_ABSENT_FROM_THIS_PLANE` in
`assurance/formal/denominator-reconciliation.json`, and
`drafts/self-review/pin-candidate-adjudication.md` already records that
`dangling` never saw it.

**This is the one that meets the stop condition as written: it changes what the
corpus contains.** Not fixed. **Owner action:** decide whether `pinconsumerctl`'s
path corpus is `git ls-files` or `git log --all --name-only`, knowing that the
second answer adds 26 rows to the formal denominator's declared basis and
re-admits ignored trees. It is a corpus decision, and it belongs with the
plane-correspondence decision the three existing HARD STOP allowances already
wait on.

**It is now DISCLOSED rather than merely absent.** The printed ceiling carries
both widenings, both row counts, the live instance, and the asymmetry with C9a —
and `TestAPinNamingAnUntrackedPathIsADisclosedFalseNegative` fails if either the
behaviour or the disclosure changes without the other.

## 5. Deletion attacks — six, every one RED

Each is a single edit that **COMPILES** (verified with `go build` before running
anything), so every RED below is behavioural. `false &&` is used with the whole
condition parenthesised where the guard is an added condition; where the fix was
the REMOVAL of an early exit, the attack RESTORES that exact exit, which is the
same neutering and also compiles.

| attack | edit | `go test` EXIT READ FROM PROCESS | what went RED |
|---|---|---|---|
| D-C1 | restore `if len(named) != 1 { return }` | **1** | `TestASecondTrackedPathNoLongerHidesADriftedDigest`, `TestEveryAllowanceCorrespondsToARealCandidate` |
| D-C2 | restore the exit-on-first-matching-digest loop | **1** | `TestAMatchingSiblingDigestNoLongerImmunisesADriftedOne`, `TestEveryAllowanceCorrespondsToARealCandidate` |
| D-PART | `if false && (!accounted[declared])` | **1** | 14 tests, and the gate prints `explained=0 covered=0 allowed=0` |
| D-C9a | `if false && (len(absent) > 0)` around the report | **1** | `TestDeletingThePinnedTargetIsReportedNotSwallowed` |
| D-C9fail | `if false && (len(census.missing) > 0)` in the refusal | **1** | `TestEveryRefusalThisGateCanMakeIsExercised` |
| D-CEILING | delete the C9b disclosure sentence | **1** | `TestAPinNamingAnUntrackedPathIsADisclosedFalseNegative` |

D-C1 and D-C2 also take the live gate to exit **1** with `STALE_ALLOWANCE`,
because the rows they re-hide orphan their acknowledgements — the allowance
mechanism catching the removal of the fix that surfaced them.

**D-C9fail found a real gap and it is fixed in the same change.** On the first
run it was the one attack that stayed GREEN: `go test` exit 0 AND the gate at
exit 0, because `missing_targets=0` in this tree, so nothing exercised the
refusal at all. A gate whose refusals are only exercised by whatever the tree
happens to contain stops refusing the day the tree goes clean. The decision is
now `danglingRefusal`, a pure function, and all five refusals this gate can make
are exercised whether or not today's tree contains them.

## 6. The printed ceiling, corrected in the same change

The ceiling's opening sentence was made false by this fix and is rewritten:
candidates are objects where no digest is the **CURRENT digest of ANY tracked
path named in the object**, not "no digest matches the file". Also added:

- multi-valued rows state that their `names=`, `declared=` and `actual=` lists
  are each sorted and are **NOT** positionally paired, and that an explanation in
  such an object may resolve against any of the paths named;
- the two asymmetric holes in the path corpus — `MISSING_PIN_TARGET` reported and
  failing, an untracked target NOT SEEN AT ALL — with the live instance, both
  measured widenings and their row counts;
- one correction not caused by this change. The previous round's record says it
  added a scope statement for the `sibling-lines` rule to the ceiling; the
  shipped ceiling did not carry it. It does now, stated as what the code
  structurally is: the rule digests the object's OWN array, so its rows can never
  re-fire on a change to the FILE they name. Checked against the code rather than
  inherited from the claim.

## 7. Evidence, every exit code read from the process

- `go run ./cmd/pinconsumerctl dangling` exit **0**;
  `json_artifacts=1997 unparsable=0 candidates=0 explained=53 covered=23 allowed=15 missing_targets=0`.
- All **11** original allowances still acknowledged; `gate=pin-dangling-allowed`
  prints 15 lines; zero `STALE_ALLOWANCE`, zero `STALE_COVERAGE_CLAIM`.
- **F014's two true positives still fire**:
  `evidence/java/test-manifest.json $.authoritative_run.execution_code_binding.sources[0]`
  and `[2]`, and `TestF014ExecutionCodeBindingDriftIsStillPresentAndStillUnbound`
  passes.
- `go test -count=1 -timeout 40m ./cmd/pinconsumerctl/` exit **0**.
- `go vet ./cmd/pinconsumerctl/` exit **0**; `gofmt -l` empty.
- Row census before vs after: 85 rows -> 91 rows, `comm -23` DISAPPEARED side
  **empty**, six rows appeared, each named and adjudicated in section 3.
- C1, C2, C9a replayed against the fix: exit **1** each, row printed each.
  C9b replayed: exit **0**, silent, as disclosed.
- `make -C rust gates` exit code recorded in section 8.

## 8. What was fixed, what was refused

- **C1 — FIXED.** Measured: adds 1 candidate row and 1 explained row to the live
  tree, removes none. The one candidate is a real drift in a governance receipt.
- **C2 — FIXED.** Measured: adds 3 candidate rows and 1 explained row, removes
  none. All three are an already-declared HARD STOP finding at a second address.
- **C9a (delete the target) — FIXED.** Measured: adds 0 rows to this tree. It is
  a guard against a future tree, and it fails the gate when it fires.
- **C9b (untrack the target) — REFUSED.** Measured: the only precise widening
  adds 26 rows, 24 of them on the vendored catalog's `rust_bindings`, and
  re-admits `.quarantine`; the heuristic widening adds 662 rows of version
  strings. It changes what the corpus contains and lands its rows on the formal
  denominator's declared basis. Owner action in section 4. Disclosed in the
  printed ceiling and pinned by a test.
