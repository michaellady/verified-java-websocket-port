# US-019 landing: the line merged, and the three gate failures it cost resolved

**Status:** COMPLETE on `claude/us019-landing`. The merge of this branch into
mainline is the coordinator's and is deliberately not done here.

This record covers the work `OA-pr4-fast-forward` ruled on 2026-09-04, plus a
second ruling, `OA-drive-until-open-branch`, which had to be applied in the same
work because the merge rewrites the file it lands on.

## 1. What merged

`origin/claude/us019-survivor-residue` at `caa44e5`, which carries
`origin/claude/us019-survivor-closure-2` at `f9b9520` — the head where the
70-survivor floor was measured — and `claude/us019-native-run` beneath it.

The merge brings two trees that **did not exist on mainline at all**:
`internal/autobahnsuite` and `rust/autobahn-controls`. That absence, not any
disagreement about the work, is why the US-019 line could not land: every test
written against those packages could only run on that branch, and the survivor
sweep's evidence could not be cited from a plan that could not see them.

Exactly one conflict: `assurance/plan/task-graph.json`. Both sides were
additive and it was resolved as a **union by id**, not by taking a side. The
union was checked rather than trusted:

- Neither side removed an id present in the merge base, so rule 12 has nothing
  to explain. This was asserted in the merge script, not eyeballed.
- Three ids existed on both sides with different content:
  `T-us019-survivors-open`, `T-us019-residue-open` and
  `T-us019-residue-live-suite`. Each took the incoming version, because
  mainline's copy of each was a stub carrying `evidence: []` — written that way
  precisely because the packages it would have cited were absent. This merge
  makes them present, so the sweep's evidence is now re-derived on every
  plan-guard run instead of being unciteable.
- `ceiling` took mainline's, the only side that changed it from the base, and
  it still equals the Go constant `CeilingText` exactly.

## 2. Fix 1 of 3 — the drifted pin

Run first, to read the actual message rather than the predicted one:

```
gate=pin-dangling artifact=evidence/formal/us023-coverage-report.json
  pointer=$.inputs[4] names=evidence/linkage/rust-identity-verification.json
  declared=sha256:afc0ef4fd6231d66ad9d80d871b110a2b27682f26bcf0d7c146b99a9fbaddb49
  actual=sha256:31a625e269c28858675302575ab3ec0b6763ca16947455ac64ea40619c730924
gate=pin-dangling json_artifacts=3500 unparsable=0 candidates=1 explained=53 covered=23 allowed=15
gate=pin-dangling result=FAIL reason="a pin has drifted and is not among the declared
  allowances; read it, then either fix the pin or acknowledge it with the owner action
  it waits on"
```

**Why it drifted, traced rather than assumed.** The whole merge changes exactly
one line of `evidence/linkage/rust-identity-verification.json`: a sha256 hanging
off the `SocketError(String),` declaration. That value is the whole-file digest
of `rust/ws-testee/src/io_loop.rs`, which was confirmed by recomputing both —
mainline's copy of that source hashes to `94027fac`, this tree's to `8907b9ac`,
and those are exactly the old and new values in the diff. So the identity
document is **correct** on this tree; `claude/us019-native-run` regenerated it
when it changed the source. What was stale was the coverage report's pin *of*
that document, still naming mainline's bytes.

The fix moves `$.inputs[4]` alone, plus the one row the markdown mirrors. It is
a re-point of provenance, not a re-baselining of a measurement: no number in
either report moves. `$.inputs[7]` was checked and was **not** drifted, so it was
left alone here and moved in fix 2, where its subject actually changes.

After:

```
gate=pin-dangling json_artifacts=3500 unparsable=0 candidates=0 explained=53 covered=23
  allowed=15 missing_targets=0
gate=pin-dangling result=PASS detail="no undeclared drift; 15 acknowledged finding(s)
  each naming an owner action"
```

## 3. Fix 2 of 3 — the reconciliation, and the denominator question

Before:

```
--- FAIL: TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive (0.00s)
    coverage_test.go:213: the retained reconciliation is not what the two denominators derive
--- FAIL: TestRetainedReportsAreExactlyWhatTheEvidenceDerives (0.01s)
    coverage_test.go:232: the retained machine-readable report is not what the evidence derives
FAIL	github.com/michaellady/verified-java-websocket-port/internal/formalcoverage	0.662s
```

This is the step that could have been a re-baselining, so it was handled as one
until proven otherwise. Both artifacts were **derived into a scratch directory
outside the repository and diffed against the retained bytes with nothing in the
tree modified**. Only after the diff was read was anything written.

### Did a denominator move? No.

Every field of the report's denominator block, mainline against this tree:

```
DENOMINATOR FIELD                                     MAINLINE  THIS TREE  MOVED?
catalog_obligations                                   24        24         no
proof_targets                                         10        10         no
obligations_with_no_proof_target                      13        13         no
targets_named_by_no_obligation                        4         4          no
obligation_ids_with_no_proof_target                   13 ids    13 ids     no
target_ids_named_by_no_obligation                     4 ids     4 ids      no
catalog_rust_binding_rows_whose_source_path_is_absent 24        24         no
catalog_rust_binding_rows_measurable_on_this_plane    0         0          no
```

Nothing was absorbed because there was nothing to absorb. The reconciliation is
equal to mainline's at **every key but one**, which was established by deleting
that key from both documents and comparing the remainder for equality rather
than by reading the diff by eye.

### The one population that did grow, stated side by side

```
shipped_crate_namespaces, mainline (5):
  candidate_stub, ws_core, ws_driver, ws_oracle_harness, ws_testee
shipped_crate_namespaces, this tree (6):
  autobahn_controls, candidate_stub, ws_core, ws_driver, ws_oracle_harness, ws_testee
```

That is the merge adding the `autobahn-controls` crate, which the workspace
manifest carries as a member and whose library namespace is `autobahn_controls`.
It is a description of which crates this plane ships, not a measurement
denominator, and it is read only as supporting context for the verdict
`NAMESPACE_NAMES_NO_CRATE_SHIPPED_BY_THIS_PLANE` — a verdict that does not
change, because adding `autobahn_controls` does not make `websocket_core`
present. The four per-row obligation counts read `[10, 9, 3, 2]` before and
`[10, 9, 3, 2]` after, and every `path_state`, `namespace_state` and
`measurable_on_this_plane` is untouched.

**Everything that changed on disk, in full:** four insertions of
`autobahn_controls` into the reconciliation's namespace lists; the report's pin
of the reconciliation, in the two places the JSON carries it and the one row the
markdown mirrors, which had to move because its subject moved in the same
commit; and four `detail` strings that print the same crate list as prose, each
differing from its predecessor by exactly the inserted `autobahn_controls, ` and
by nothing else — checked by string substitution, not by reading.

The reconciliation was written first and the report re-derived against it
second, so the report pins bytes that are actually on disk rather than the ones
that were there when the commit started.

After:

```
ok  	github.com/michaellady/verified-java-websocket-port/internal/formalcoverage	0.680s
ok  	github.com/michaellady/verified-java-websocket-port/cmd/formalcoverctl	0.071s
```

pin-guard was re-run afterwards and still reads `candidates=0`, so moving the
reconciliation's bytes did not strand its pin.

## 4. Fix 3 of 3 — adapter-linkage, and the `drive_until_open` ruling

These are one commit because they are one record in the Go source: re-pinning
the fingerprint is justified *by* the ruling, so a commit that re-pinned while
the reason beside it still read `NOT RULED ON` would state something false.

Before:

```
gate=adapter-linkage branch_site=ws-testee/src/io_loop.rs:831 fn=drive_until_open
  rule=variant-in-equality evidence="ReadyState::NotYetConnected"
  fingerprint=40a62857c4563017... declared=false
gate=adapter-linkage branch_site=ws-testee/src/io_loop.rs:950 fn=drive_until_open
  rule=variant-in-equality evidence="ReadyState::NotYetConnected"
  fingerprint=40a62857c4563017... declared=false
gate=adapter-linkage finding=ADAPTER_PROTOCOL_BRANCH detail="...:831 fn drive_until_open
  branches on core protocol state ...; no declared allowance matches fingerprint 40a62857c4563017"
gate=adapter-linkage finding=ADAPTER_PROTOCOL_BRANCH detail="...:950 ... no declared
  allowance matches fingerprint 40a62857c4563017"
gate=adapter-linkage finding=STALE_PROTOCOL_BRANCH_ALLOWANCE detail="allowance for
  ws-testee/src/io_loop.rs fn drive_until_open (fingerprint 2c05c5aeae1c8921) matched no
  branch this run: the site was removed or changed, so the allowance now claims coverage
  of something that is not there"
gate=adapter-linkage verdict=FAIL detail="3 adapter architecture findings"
ac1-gates verdict=FAIL gates_passed=7/8
```

**The branch was found by its code, not by its line.** The ruling names
`io_loop.rs:745`; that number is mainline's and does not survive the merge.
Grepping the merged source for `NotYetConnected` puts the ruled decision at
`:831`, `if driver.state() != ReadyState::NotYetConnected`, now returning a
`HandshakeOutcome` carrying the straddle carryover where mainline returned a
bare `true`. Same decision, same function, moved.

**The second site is disclosed, not absorbed.** adapter-linkage fingerprints the
*enclosing function's* normalized token stream, so one allowance covers every
branch site in `drive_until_open` — and the merged function has two. The ruled
one at `:831`, and a second at `:950`,
`while cursor < rest.len() && driver.state() == ReadyState::NotYetConnected`,
which `claude/us019-native-run` added and which was not on the tree the owner
ruled against. Its character is the same readiness poll: it feeds the handshake
one byte at a time so a read cannot straddle the 101/first-frame boundary, and
the adapter still parses nothing. But the ruling's text does not name it, and it
cannot be declared apart from `:831` because the gate gives them one fingerprint
by design. So it is written into the allowance's own reason and filed as
`OA-drive-until-open-second-site` rather than counted as ruled on.

After:

```
gate=adapter-linkage branch_site=ws-testee/src/io_loop.rs:831 fn=drive_until_open ... declared=true
gate=adapter-linkage branch_site=ws-testee/src/io_loop.rs:950 fn=drive_until_open ... declared=true
gate=adapter-linkage verdict=PASS detail="adapter linkage exact over 6 production sources;
  edges exact; no protocol surface or parser branch; 4 protocol-state branch site(s) over
  27 governed core enums, all declared"
ac1-gates verdict=PASS gates_passed=8/8
```

No stale allowance remains: the entry was re-pinned rather than dropped, because
the site it covers still exists.

## 4b. A fourth failure the ruling could not have named

Running the whole suite surfaced one more red, and it is worth more than its
size because of how it hid. `record-guard prose` reported:

```
gate=record-prose step=census cardinality_sentences=277 with_enumerable_population=14
  no_enumerable_population=263 bound=13 covered=0 undispositioned=1
gate=record-prose finding=UNDISPOSITIONED_CLAIM
  record=drafts/self-review/us019-native-run-round-1.md
  field="evidence/autobahn/native-digest-manifest.json $.files" line=124
  detail="this line states a cardinality about a population this gate can enumerate,
  and no binding, coverage claim or allowance names it"
gate=record-prose result=FAIL blocking=1
```

**Why neither parent could see it**, established with git rather than inferred:

```
cmd/recordguardctl/prose.go                      mainline: PRESENT   residue: ABSENT
drafts/self-review/us019-native-run-round-1.md   mainline: ABSENT    residue: PRESENT
```

The gate lives only on mainline. The record it fails on lives only on the US-019
line. This merge is the first tree that holds both, so the failure could not
have appeared on either side and could not have been predicted from either. It
is a genuine merge-interaction failure — not contention, and not a pre-existing
red I inherited and mislabelled.

**Bound, not allowed, because the sentence is right.** The stated count and the
document's array agree exactly. An allowance in this gate is for a claim that
*disagrees* with its document and must not be closed by editing the number;
that is not this case. So the sentence gets a binding that re-derives the value
from the document on every run.

One helper was needed and is disclosed rather than slipped in: the comparison is
string equality, and this is the corpus's first grouped numeral, so a sentence
written with a thousands separator could not match a derivation rendered without
one. `deriveGrouped` wraps an existing derivation and adjusts only the
rendering, to the convention the bound sentence itself uses. It stores no
expected value, so the binding table's one design rule still holds.

**The binding was proven live rather than assumed.** Perturbing the record's
number by one produced:

```
gate=record-prose finding=PROSE_DISAGREES_WITH_DOCUMENT
  record=drafts/self-review/us019-native-run-round-1.md
  field="native_digest_manifest_files" line=124
  detail="the record says 1,049, the tree derives 1,048 from
  evidence/autobahn/native-digest-manifest.json $.files"
gate=record-prose result=FAIL blocking=1
```

and the record was restored from git afterwards. After the fix:

```
gate=record-prose step=census cardinality_sentences=277 with_enumerable_population=14
  no_enumerable_population=263 bound=14 covered=0 undispositioned=0
gate=record-prose step=bindings agreeing=17 allowed=6 covered_records=1
gate=record-prose result=PASS
```

## 5. The plan

`T-pr4` is `done` with evidence plan-guard re-derives, and its evidence is
shaped so it **cannot hold on a mainline where the coordinator's merge did not
happen** — two items ask git whether the previously-absent packages are tracked,
so the plan goes red there rather than quietly reading done.

`T-us019-survivors-open` keeps the sweep's own evidence, which is citable here
for the first time. Its note previously ended by saying the three gate failures
were inherited and "none fixed here"; that sentence was true of the branch that
wrote it and is false of this one, so it now says so and points at `T-pr4`. The
round's own record still reads `EXIT 2` and was deliberately left alone: that
was a true reading of that tree, and rewriting history to match a later tree is
the drift this project refuses.

`T-drive-until-open-second-site` is added, `blocked` on the new owner action.

## 6. What I could not resolve

- **The second `drive_until_open` site is declared without having been ruled
  on.** It cannot be separated from the ruled site, because the gate pins one
  fingerprint per function. Filed as `OA-drive-until-open-second-site`.
- **Landing on mainline is not done and was not attempted**, per the standing
  constraint that the coordinator merges. Nothing was pushed to
  `claude/feature/verified-java-websocket-port`, and PR #4 and PR #5 were not
  touched on GitHub — no label, no comment, no state change.
- **No owner gate was triggered.** No AWS run, no benchmark run, no Autobahn
  re-run, no `internal/lab` execution path. The six survivors that sit past
  `/getCaseCount` therefore remain open under `T-us019-residue-live-suite`,
  which is still blocked on `OA-autobahn-reruns`.
- **The hard-stop reported by the previous round is untouched.** That round's
  own record states that re-enumerating its four Go sources finds 111
  if-conditions where the round counted 110, and that its enumerator is
  gitignored and cannot be re-derived. Nothing here closes that, and nothing
  here depends on it: this landing changed no site count.

## 7. Whole-suite gates reading

`make -C rust gates`, run with both required exports.

One scope note, because a run cannot contain its own output: the suite was run
on the tree as of the plan commit, and this section was appended afterwards. The
three targets that READ records and the plan — `record-content-precondition`,
`record-prose` and `plan-guard` — were therefore re-run against the finished
file, and all three still pass, with the prose census unchanged at zero
undispositioned. The compile-and-test targets are untouched by a markdown
append.

**`make -C rust gates` exits 0.** Twelve targets, no failure anywhere in the
run: a search of the whole log for a failing verdict, a Go `--- FAIL`, or a
bare `FAIL` line returns zero.

The census each target printed:

```
gate=fixture-liveness-guard step=selfcheck cases=7 firing=4 silent=3 result=PASS
gate=fixture-liveness-guard step=budget-anchors budgets=1 result=OK
gate=fixture-liveness-guard result=PASS

gate=record-content-precondition step=selfcheck cases=16 firing=8 silent=8 result=PASS
gate=record-content-precondition census SUPERSEDED
  record=drafts/self-review/normalization-collision-audit-WIP.md signals=2
  superseded_by=drafts/self-review/normalization-collision-audit.md
gate=record-content-precondition step=census records=80 unfinished=0 superseded=1 finished=79
gate=record-content-precondition result=PASS

gate=record-prose step=corpus records=91 markdown=85 statements=6 bindings=23
gate=record-prose step=census cardinality_sentences=277 with_enumerable_population=14
  no_enumerable_population=263 bound=14 covered=0 undispositioned=0
gate=record-prose step=bindings agreeing=17 allowed=6 covered_records=1
gate=record-prose result=PASS

gate=pin-dangling json_artifacts=3500 unparsable=0 candidates=0 explained=53
  covered=23 allowed=15 missing_targets=0
gate=pin-dangling result=PASS detail="no undeclared drift; 15 acknowledged finding(s)
  each naming an owner action"

gate=task-graph nodes=45 done=24 ready=7 in_progress=0 blocked=14 owner_actions=29 open=19
gate=task-graph result=PASS detail="every done node's evidence re-derived; 7 ready,
  14 blocked on 19 open owner action(s)"

gate=go-suite result=PASS detail="64 package(s) run of which 48 carry a test file,
  1 excluded by name with a reason that was RUN and still fails, 5 test file(s) not
  compiled by this run"

gate=forbid-unsafe verdict=PASS
gate=dependency-inventory verdict=PASS detail="workspace has 0 out-of-workspace
  dependencies; inventory agrees (0 entries)"
gate=msrv verdict=PASS detail="declarations consistent (channel=rust-version=intake=1.95.0);
  workspace builds under MSRV toolchain 1.95.0-x86_64-unknown-linux-gnu"
gate=license verdict=PASS
gate=audit verdict=PASS detail="zero out-of-workspace dependencies (empty audit surface);
  audit tools absent, execution pending availability"
gate=lockfile verdict=PASS detail="cargo build --locked and cargo metadata --locked
  succeeded; Cargo.lock byte-identical, git-tracked and equal to HEAD"
gate=canaries verdict=PASS detail="polarity proven: good-scaffold passed scan/clippy/test
  (exits 0/0/0); bad-scaffold failed scan and clippy as required (exits 1/101)"
gate=adapter-linkage core_sources=16 governed_protocol_enums=27 seam_enums=1
  branch_sites=4 declared_allowances=2 cfg_test_items_skipped=2
gate=adapter-linkage verdict=PASS
ac1-gates verdict=PASS gates_passed=8/8

ok: evidence/java/behavior-delta-ledger.json equals the regeneration (59 records,
  head sha256:f10dd526..., document schema 1.2.0)
ok: ledger integrity verified (frozen prefix through sequence 35, ..., 
  unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
ok: evidence/governance/owner-decision-digests.json equals the derivation and
  7 governance record digest(s) recomputed from the protected store and matched

oraclerankctl: 640 propositions adjudicated; 589 Java/Rust agreements, 39 of them
  overridden by a higher oracle and every one enrolled in
  evidence/oracle-hierarchy/adjudication-register.json
```

Two readings in that list are worth naming, because a green line can hide a
refusal:

- **ledger-gates did not refuse.** It recomputed governance digests out of the
  protected store, which it can only do when `VJWP_PROTECTED_STORE` is set. A
  refusal there prints as an error and is never a pass, so the fact that it
  reports recomputed digests is what shows the export was in place.
- **go-suite's excluded package was RUN and still fails.** `internal/lab` needs
  a Darwin sandbox and cannot pass on this host. The gate does not skip it: it
  runs it and requires it to fail, so an exclusion cannot outlive its reason.
  That is a property of the base and not of this branch, and it was checked
  before the run rather than explained after it.

No owner gate was triggered to produce this reading: no AWS host, no benchmark,
no Autobahn re-run, and `internal/lab`'s execution path was not entered.

## Coordinator addendum: the scan corpus grew, and that was not disclosed

Added at merge. This round's record answered "did a denominator move?" for the
reconciliation report and answered it well, but it did not name a second number
that moved in the same merge, and the standing rule makes any corpus shift a
thing to report rather than a thing to notice later.

`pin-dangling` went from `json_artifacts=1997` on mainline to `json_artifacts=3500`
here. That is not a re-baselining and it is not a defect; it is the scan corpus
growing because the tree grew. But it is a 75% change in the population a gate
reports scanning, and a reader comparing two gate logs across this merge would
otherwise have to work out for themselves whether something had been widened.

Measured rather than asserted. `json_artifacts` is exactly the count of tracked
`.json` files, which reproduces on both sides:

```
tracked .json at mainline HEAD : 1997
tracked .json at this merge    : 3500
```

The property that matters is not the growth but whether anything was LOST, and
the answer is none. Sorting both lists and taking `comm -23`:

```
disappeared : 0
added       : 1503
```

and the additions are where the merge says they should be — 1499 under the
Autobahn evidence tree, 3 under the Autobahn harness directory, 1 in the
autobahn-controls crate. Every path that was scanned before is still scanned.

Every MEASUREMENT denominator is unchanged across the merge, re-derived here
rather than read from the report above: the oracle census still prints 640
propositions, 589 Java/Rust agreements and 39 overridden; the public corpus is
still 74 and the handshake corpus 49, both asserted by constants with
want-checks; and the Autobahn manifest is still 247.

So: one population grew for a stated reason with nothing removed, and no
measured quantity moved. The distinction is the whole point of the rule — a
corpus that grows because files arrived is not a denominator that was moved to
make something pass — and it should be stated in the record rather than left
for the next reader to reconstruct.
