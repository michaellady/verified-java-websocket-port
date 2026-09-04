# US-019 survivor closure — 64 of 70 swept checks bound to a probe, 6 proved unreachable, 0 left undecided

Recorded 2026-09-03 from tool output, on branch `claude/us019-survivor-closure-2`
at head `46c75a3`, in an isolated worktree at `/home/user/vjwp-survivors`.
Self-review by the loop, not an independent review:
**OWNER_ATTESTED_NOT_INDEPENDENT**.

The branch is `origin/claude/feature/verified-java-websocket-port` at `c738b81`
with `origin/claude/us019-native-run` at `6416805` merged in (merge `a620dfe`,
no conflicts). The merge was necessary because `internal/autobahnsuite`,
`cmd/autobahnsuitectl` and `rust/autobahn-controls` exist **only** on
`claude/us019-native-run` — `git ls-tree origin/claude/feature/verified-java-websocket-port internal/`
names no `autobahn` path — so the checks under attack are not present on
mainline at all.

Nothing was merged or pushed to mainline. No AWS run, no benchmark run and no
Autobahn re-run was taken. `origin/codex/race-catchup` was read and never
written.

---

## 1. What this round measured, and why the numbers are NOT round 3's

Round 3 swept 85 `if`-guarded sites with a naive `false &&` prefix and recorded
25 RED, 52 GREEN and 8 that failed to compile. It closed 7, leaving 45 open.

This round did **not** continue that sweep. It re-ran the sweep from scratch at
this head with a stricter mutation, so its denominator is its own and the two
counts must never be added or subtracted from one another. The two differences:

1. **The mutation is a rewrite, not a prefix.** `if [init;] COND {` becomes
   `if [init;] false && ( COND ) {`. The parentheses are load-bearing:
   `false && A || B` parses as `(false && A) || B`, which does **not** disable a
   top-level `||`. Round 3's prefix silently under-disabled every such site.
   The rewriter is `.sweep/mutate.py` in this worktree; it never deletes code.
2. **It compiles everywhere.** Carrying the init statement through, rather than
   putting `false &&` in front of it, means `if x, ok := m[k]; false && ok {`
   compiles. **BUILD-BREAK count this round: 0**, against round 3's 8. Those 8
   sites are therefore swept here for the first time, and their readings are
   real readings rather than compile errors.

The site enumeration is also wider: 110 sites against round 3's 85, because the
parser walks `} else if` and multi-line conditions that a `^\s*if ` grep misses.

Baseline sweep, every exit read from the process, `go vet` then
`go test -count=1 ./internal/autobahnsuite/ ./cmd/autobahnsuitectl/` after each
single mutation:

| Outcome | Count |
| --- | ---: |
| RED — something went red | 40 |
| **GREEN — survived, nothing noticed** | **70** |
| BUILD-BREAK — proves nothing | **0** |
| Sites swept | 110 |

Raw readings: `.sweep/baseline.tsv` (110 rows, one per site).

### 1.1 THE CEILING ON 70 — read this before quoting the number

**70 is a FLOOR on the survivors, not a total, and 110 is not "every check on
this branch".** The sweep covers `if`-guarded checks in exactly four files:
`internal/autobahnsuite/{baseline,independence,reconcile,suite}.go`.

Not swept, and therefore not counted in either direction:

- **Every `switch` arm.** `VerifyRegisterIsExact`'s stale-entry and
  class-mismatch arms, `Reconcile`'s behaviour classification, `Discriminate`'s
  subject dispatch and `DiscriminateAgainstBaseline`'s whole `switch` are not
  `if` lines and were never mutated.
- **Every Rust-side check** in `rust/autobahn-controls/src` and
  `rust/ws-testee/src/agent.rs`, which this branch also adds.
- **Every boolean conjunct inside a composite expression.** `ledger.Reconciles`
  is assigned from six `&&`-joined conditions on one statement; the sweep
  disables the enclosing `if`, never one conjunct.

A later round that widens the sweep will get a larger floor, and must report it
with its own ceiling in the same way.

---

## 2. The result: 64 closed, 6 proved unreachable, 0 left undecided

With the probes in place the same 110-site sweep was re-run
(`.sweep/final.tsv`). **64 of the 70 survivors turned RED.** The 6 that stayed
GREEN are exactly the 6 that were independently proved unreachable by reading
the code **before** the second sweep ran — the sweep and the reading agree
without either being fitted to the other.

| | Count |
| --- | ---: |
| Survivors closed — a named probe goes RED when the check is disabled | **64** |
| Survivors proved UNREACHABLE, with the construction that cannot exist | **6** |
| Survivors still open and undecided | **0** |

The probes are one new file, `internal/autobahnsuite/round4_closure_test.go`,
sha256 `cc7aa32e4766d29cc5bde30275e1a30b21bb778da84fb490d383e73e32490ac9`,
1548 lines, 56 top-level tests, 45 of them distinct probes that appear in the
site-to-probe map. No production file was edited: `git diff` against
`origin/claude/us019-native-run` over the four swept files is empty.

### 2.1 What made these closable when round 3 could not close them

Round 3 filed 45 survivors in three classes and left all three. Each class had
one wrong assumption in it, and naming them is the substance of this round.

**"Defensive nil/empty guards on inputs no caller supplies."** Every one of
those functions is EXPORTED. The caller nothing produces is the test, and a
`go test` process that panics is a failing test, not a passing one. Deleting
`manifest == nil` in `Reconcile` does not degrade an error into nothing — it
degrades it into `len(manifest.Cases)` on a nil pointer. All 11 such guards are
closed by calling the function with the input directly.

**"Whole-feature control-flow selectors: disabling one skips a feature wholesale
and no test notices."** That a feature is skipped wholesale is what makes it
easy to detect, not hard: assert the observable the feature produces.
`casesDir == ""` is closed by asserting `TimedOut == -1`, because -1 means
"nobody looked" and 0 means "the run had no timeouts" and those are different
published claims.

**"Checks carrying a claim that no probe reaches."** Reached here by rewriting
ONE field of a committed report and leaving every other field genuine. Five
probes needed a mutable copy of the whole dev report tree
(`mutableTree`), so that a case identity can be added to or removed from BOTH
roles' indexes and case directories at once and every count still balances.

**The failure mode round 3 diagnosed and this round had to keep avoiding.** A
probe that asserts only "an error came back" is satisfied by whichever check
fires first. Deleting most of these does not make the function succeed — it
makes it succeed at blaming something else. `len(sources) == 0` disabled still
refuses, with "no client-role (fuzzingserver) source", which sends a reader
looking for a report that was never asked for. **Every probe here asserts the
refusal TEXT or the exact `(case, field)` of a finding, never a count.**

### 2.2 The site-to-probe map

Read as: with this line's condition rewritten to `false && ( ... )`, and no
other change, that test goes RED; with the line restored, the whole package
suite is green. Both readings taken from the process.

**`internal/autobahnsuite/baseline.go`** — 29 closed

| Line | The check, verbatim | Probe that goes RED when it is disabled |
| ---: | --- | --- |
| 153 | `err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 166 | `err := json.Unmarshal(raw, &document); err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 172 | `!strings.HasPrefix(ref, autobahnRefPrefix)` | `TestTheLedgerIndexOnlyIndexesAutobahnRefsThatNameACase` |
| 176 | `!found \|\| caseID == ""` | `TestTheLedgerIndexOnlyIndexesAutobahnRefsThatNameACase` |
| 198 | `manifest == nil` | `TestCompareToBaselineRefusesANilManifestRatherThanPanicking` |
| 205 | `err != nil` | `TestCompareToBaselineNamesWhichOfItsTwoIndexesItCouldNotRead` |
| 209 | `err != nil` | `TestCompareToBaselineNamesWhichOfItsTwoIndexesItCouldNotRead` |
| 226 | `subjectRan` | `TestAnUnobservedCaseCarriesWhicheverSideDidRunIt` |
| 229 | `baselineRan` | `TestAnUnobservedCaseCarriesWhicheverSideDidRunIt` |
| 345 | `len(agreement.DivergenceDetail) == 0` | `TestTheDivergenceSuffixIsEmptyWhenNothingDiverges` |
| 389 | `manifest == nil` | `TestVerifyComparisonDocumentRefusesANilManifestRatherThanPanicking` |
| 393 | `err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 404 | `err := json.Unmarshal(raw, &document); err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 423 | `err != nil` | `TestVerifyComparisonDocumentRefusesAnUnreadableLeg` |
| 430 | `document.ExpectedCaseCount != len(manifest.Cases)` | `TestTheDocumentsExpectedCountMustBeTheManifestsCount` |
| 440 | `len(document.Cases) != len(manifest.Cases)` | `TestTheDocumentMustCarryARowForEveryManifestCase` |
| 458 | `caseID == ""` | `TestARowWithNoCaseIdIsReported` |
| 462 | `_, duplicate := rows[caseID]; duplicate` | `TestADuplicatedCaseRowIsReported` |
| 470 | `!present` | `TestAManifestCaseTheDocumentOmitsIsNamed` |
| 474 | `required, ok := row["strict_pass_required"].(bool); ok && required != entry.StrictPassRequired` | `TestARowMayNotRestateTheManifestsStrictPassRequirement` |
| 509 | `!differs && listed[caseID]` | `TestASummaryListEntryThatNamesAnAgreeingCaseIsReported` |
| 516 | `findings[i].CaseID != findings[j].CaseID` | `TestFindingsAreOrderedByCaseFirstThenField` |
| 559 | `r == nil` | `TestEntryForRefusesANilRegisterAndMatchesOnBothCaseAndRole` |
| 573 | `err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 577 | `err := json.Unmarshal(raw, &register); err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 591 | `err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 604 | `err := json.Unmarshal(raw, &document); err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 624 | `register == nil` | `TestVerifyRegisterAgainstLedgerReportsANilRegisterRatherThanPanicking` |
| 656 | `agreement == nil` | `TestVerifyRegisterIsExactReportsANilAgreementRatherThanPanicking` |

**`internal/autobahnsuite/independence.go`** — 6 closed

| Line | The check, verbatim | Probe that goes RED when it is disabled |
| ---: | --- | --- |
| 73 | `err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 77 | `err := json.Unmarshal(raw, &config); err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 94 | `manifest == nil` | `TestVerifyManifestIndependenceReportsANilManifestRatherThanPanicking` |
| 154 | `!present[family]` | `TestEverySelectedFamilyMustBeRepresentedInTheManifest` |
| 186 | `config == nil` | `TestVerifyManifestIndependenceSkipsANilConfigRatherThanDereferencingIt` |
| 214 | `counts[value] < 0` | `TestSameSetComparesMultisetsNotJustLengths` |

**`internal/autobahnsuite/reconcile.go`** — 10 closed

| Line | The check, verbatim | Probe that goes RED when it is disabled |
| ---: | --- | --- |
| 125 | `manifest == nil` | `TestReconcileRefusesANilManifestRatherThanPanicking` |
| 132 | `err != nil` | `TestAnIndexReportingMoreThanOneAgentIsRefused` |
| 152 | `err != nil` | `TestACaseReportThatCannotBeReadOrParsedIsNamedAsSuch` |
| 163 | `casesDir == ""` | `TestTimedOutIsReportedUnavailableRatherThanZeroWhenNoCasesDirectoryIsGiven` |
| 192 | `filtered[entry.CaseID]` | `TestAFilteredCaseIsCountedFilteredAndNotMissing` |
| 241 | `report.WasOpenHandshakeTimeout` | `TestEachTimeoutFlagIsCountedOnItsOwnAxisAndOverlaid` |
| 244 | `report.WasCloseHandshakeTimeout` | `TestEachTimeoutFlagIsCountedOnItsOwnAxisAndOverlaid` |
| 352 | `ledger == nil` | `TestDiscriminateRefusesANilLedgerRatherThanPanicking` |
| 355 | `!ledger.Reconciles` | `TestAVerdictOnANonReconcilingLedgerSaysSoRatherThanScoringIt` |
| 369 | `ledger.Executed == 0` | `TestARunThatScoredNothingCannotSatisfyAC3` |

**`internal/autobahnsuite/suite.go`** — 19 closed

| Line | The check, verbatim | Probe that goes RED when it is disabled |
| ---: | --- | --- |
| 192 | `err != nil` | `TestBuildManifestNamesTheSourceInputItCouldNotRead` |
| 196 | `err := json.Unmarshal(raw, &byAgent); err != nil` | `TestEveryReaderNamesItsOwnReadAndParseFailure` |
| 199 | `len(byAgent) != 1` | `TestAnIndexReportingMoreThanOneAgentIsRefused` |
| 212 | `err != nil` | `TestACasesDirectoryThatCannotBeScannedIsNamedAsSuch` |
| 218 | `err != nil` | `TestACaseReportThatCannotBeReadOrParsedIsNamedAsSuch` |
| 222 | `err := json.Unmarshal(raw, &report); err != nil` | `TestACaseReportThatCannotBeReadOrParsedIsNamedAsSuch` |
| 225 | `report.ID == "" \|\| report.Case < 1` | `TestACaseReportWithNoUsableIdOrOrdinalIsRefused` |
| 228 | `prior, seen := reports[report.ID]; seen && prior.Case != report.Case` | `TestOneCaseIdBoundToTwoOrdinalsIsRefused` |
| 234 | `len(reports) == 0` | `TestACasesDirectoryWithNoReportsIsRefused` |
| 257 | `len(sources) == 0` | `TestBuildManifestNamesTheEmptySourceListRatherThanFailingLater` |
| 268 | `err != nil` | `TestBuildManifestNamesTheSourceInputItCouldNotRead` |
| 272 | `err != nil` | `TestBuildManifestNamesTheSourceInputItCouldNotRead` |
| 275 | `len(entries) != len(reports)` | `TestASourceWhoseIndexAndReportCountsDifferIsRefusedByCount` |
| 281 | `!ok` | `TestASourceWhoseIndexNamesACaseWithNoReportIsRefused` |
| 294 | `prior, seen := target[caseID]; seen && prior != report.Case` | `TestTwoSourcesInOneRoleMustAgreeOnEveryCaseNumber` |
| 321 | `len(selectedOrdinals) == 0` | `TestAManifestNeedsBothARoleThatNumbersAndARoleThatOrdinals` |
| 325 | `len(suiteNumbers) == 0` | `TestAManifestNeedsBothARoleThatNumbersAndARoleThatOrdinals` |
| 341 | `family+".*" == nonselected.Family` | `TestACaseFromADeclaredNonselectedFamilyIsRefused` |
| 357 | `len(cases) != SelectedCaseCount` | `TestTheExpandedCaseCountMustBeThePinnedCount` |

---

## 3. The 6 that are NOT open — each is UNREACHABLE, and the recommendation is plain

These are not survivors this round failed to close. **A check no input can make
true is not a check**, and leaving them filed as "open" would misdescribe them
for a fourth time. Each proof was written from the code before the second sweep
ran; the second sweep then found exactly these 6 and no others still GREEN.

### 3.1 `independence.go:108` — `lab.AutobahnSelectedCaseCount != SelectedCaseCount`

Both operands are untyped compile-time constants:
`internal/lab/autobahn_controller.go:39` declares
`AutobahnSelectedCaseCount = 247` inside a `const (` block, and
`internal/autobahnsuite/suite.go:35` declares `SelectedCaseCount = 247` in one.
The comparison has the same value on every call for the life of a build. **No
runtime input can make it true**, so no test can distinguish the guarded from
the unguarded form.

This is not vacuous — it is a **build-time consistency assertion written as a
runtime branch**. Editing either constant makes it fire on every call rather
than at compile time, which is the worst of both: it does not stop the build,
and it costs a comparison per invocation to say something that was already
decided.

**RECOMMENDATION: convert it to a compile-time assertion and delete the branch.**
The idiomatic form is a package-level `var _ = [1]struct{}{}[SelectedCaseCount-lab.AutobahnSelectedCaseCount]`,
which fails to compile when the two drift and cannot be skipped by any caller.
Round 2's record presents this check as "making a drift between two
independently sourced numbers fail rather than silently agreeing"; that sentence
is true of the compile-time form and cannot be demonstrated of the current one.
Not applied here — it edits production code on a US-019 branch under BLOCK.

### 3.2 `baseline.go:201` — `register == nil` in `CompareToBaseline`

MASKED by `baseline.go:559`. Inside `CompareToBaseline` the parameter `register`
is used at exactly one place, `register.entryFor(role, entry.CaseID)` at line
256 — verified by reading every occurrence in lines 193-289 — and `entryFor` is
declared on the pointer receiver with its own `if r == nil { return nil }` at
line 559. A nil `register` therefore behaves identically with and without line
201. **No observable differs**, so no probe can exist while 559 stands.

559 itself IS discriminable and is closed above by
`TestEntryForRefusesANilRegisterAndMatchesOnBothCaseAndRole`, which calls it on
a nil receiver directly.

**RECOMMENDATION: delete line 201.** It is a second nil guard for a value whose
only consumer already guards nil. Keeping it costs nothing at runtime but it
inflates the count of "checks" this package is credited with by one that
nothing can ever fail.

### 3.3 `reconcile.go:172` — `globErr != nil`

MASKED by `suite.go:212`. `Reconcile` calls `readCaseReports(casesDir)` under
`if casesDir != ""` at line 150; `readCaseReports` globs
`filepath.Join(dir, "*.json")` at `suite.go:211` and returns `scan %s: %w` on
error. The second block at line 169 is guarded by the **same** `casesDir != ""`
and globs the **byte-identical** pattern `filepath.Join(casesDir, "*.json")`.
`filepath.Glob` fails only on `ErrBadPattern`, which is a property of the
pattern alone. So any input that makes line 171's glob fail already made line
151's glob fail, and `Reconcile` returned before reaching line 172.

`suite.go:212` is reachable and is closed above by
`TestACasesDirectoryThatCannotBeScannedIsNamedAsSuch`, which passes a directory
path containing an unclosed `[`.

**RECOMMENDATION: keep the error return but stop counting it as a check.** It is
correct defensive code at a call boundary; it is not a distinct constraint on
any input.

### 3.4 `suite.go:312` — `err != nil` on the second `readIndex`

MASKED by `suite.go:268`. `BuildManifest` walks `sources` twice. Loop one
(line 266) calls `readIndex(source.IndexPath)` and returns on error at 268.
Loop two (line 310) calls `readIndex(source.IndexPath)` for the **same paths**.
`readIndex` is a pure function of the named file's bytes and `BuildManifest`
writes no file, so loop two can only fail where loop one already returned —
unless an external writer changes the file between the two loops, which no
caller of this package can arrange from inside one call.

**RECOMMENDATION: hoist the first loop's result instead of re-reading.** Reading
each index twice is where the unreachable branch comes from; caching `entries`
from loop one removes the second read, the branch, and one filesystem round trip
per source. Not applied here for the same reason as 3.1.

### 3.5 and 3.6 `suite.go:332` and `suite.go:336` — the two `!ok` lookups

MASKED by `suite.go:315` together with `321`/`325`, and this is the one proof in
this section that is an argument rather than an inspection, so it is written out
in full.

Let `E_s` be source `s`'s index entries and `C` the union `caseIDs`, which loop
one fills from every source's entries, so `E_s` is a subset of `C` for every `s`.
Line 315 refuses unless `len(E_s) == len(C)` for every `s`. A subset of `C` with
`|C|` elements IS `C`. Therefore, past line 315, `E_s == C` for every source.

Line 321 refuses unless `selectedOrdinals` is non-empty, which requires at least
one client-role source `s` to have contributed; loop one wrote
`selectedOrdinals[caseID]` for every `caseID` in that source's `E_s`, which is
`C`. So `selectedOrdinals` has a key for every element of `C`, and line 332's
`!ok` — looked up with `caseID` ranging over `C` — cannot be true. Line 336 is
the same argument through `suiteNumbers` and line 325.

Confirmed empirically as well: `TestEverySourceMustCoverTheIdenticalCaseSet`
constructs the only shape that would reach 332 (one role's source short by one
case) and measures that **315 answers first**, with
`sources must agree exactly`.

**RECOMMENDATION: keep them, and say in the code that 315 is what makes them
unreachable.** Unlike 3.1-3.4 these are cheap insurance against a future edit
that weakens 315, and the argument above depends on 315 in a way a later reader
will not reconstruct unaided. What must stop is counting them as checks the
suite demonstrates; they are consequences of 315, and 315 is already RED under
deletion.

---

## 4. Findings

### 4.1 A run that scored NO cases satisfies AC3 if one guard is removed

`reconcile.go:369`, `ledger.Executed == 0`, was a survivor. The probe that
closes it, `TestARunThatScoredNothingCannotSatisfyAC3`, reconciles an index
carrying an agent and zero cases against a zero-case manifest. That ledger
**reconciles**: the scope identity is `0 = 0 + 0 + 0`, the class identity is
`0 = 0+0+0+0+0+0`, `Missing` is 0, unexpected is 0, disagreements are 0. Every
AC3 equation is then trivially satisfied at zero — `strict_pass_all` is true,
`executed == selected`, `passed == executed`, `strict_required_not_ok == 0` —
so with the guard disabled `Discriminate(SubjectUnderTest, ledger).AsExpected`
comes back **true**. The strongest verdict this package can issue would be
issuable by a report containing nothing.

The guard is present and the behaviour is correct at this head. What was absent
is any test that would have noticed its removal, and the non-reconciling guard
one line above cannot answer for it, because this ledger reconciles.

### 4.2 The committed dev fuzzingclient run carries 32 connection-drop timeouts

Measured while building the timeout probes, and worth recording because the
first version of that probe asserted `ConnectionDropTimeouts == 1` and went red
against the real fixture. Over
`evidence/autobahn/dev-aarch64-nonauthoritative/fuzzingclient-run1/cases`:
`wasOpenHandshakeTimeout` 0, `wasCloseHandshakeTimeout` 0,
`wasServerConnectionDropTimeout` **32**, cases carrying any timeout flag 32 of
247. Case `1.1.1` carries none, which is why the probes use it.

The probe now asserts a DELTA against a measured unmutated baseline and fails
loudly if `1.1.1` ever gains a flag, so it cannot go quietly stale.

### 4.3 `pinconsumerctl consumers` answers about CONTENT, and says "nobody" precisely when a pin has already drifted

Run on this branch:

```
go run ./cmd/pinconsumerctl consumers evidence/linkage/rust-identity-verification.json
gate=pin-consumers target=evidence/linkage/rust-identity-verification.json
  sha256=31a625e269c28858675302575ab3ec0b6763ca16947455ac64ea40619c730924 consumers=0
    nothing in the tree pins this file's current content
```

`consumers=0` is not "this file is safe to change". `evidence/formal/us023-coverage-report.json`
and its `.md` both pin that path — at the STALE digest
`sha256:afc0ef4f...`, confirmed by `grep -rl` over the tree. The tool matched on
the file's CURRENT digest, found nobody, and reported nobody.

So the tool is exact about the question it answers and that question is not the
one an operator asks before editing a file. **RECOMMENDATION: report
path-pinning consumers alongside content-pinning ones, and mark a path
consumer whose pinned digest differs from the file on disk as ALREADY DRIFTED**
— which is strictly more information at the moment it is most wanted. Recorded,
not fixed: `cmd/pinconsumerctl` is another track's tool.

### 4.4 A defect inherited from `claude/us019-native-run`, reproduced standalone

`internal/formalcoverage` and `cmd/formalcoverctl` are RED on this branch. They
are RED on `origin/claude/us019-native-run` at `6416805` on its own (measured in
a separate detached worktree, exit 1), and they are GREEN on mainline `c738b81`
in that same worktree (exit 0). This branch's tree is **byte-identical to
mainline** across `assurance/formal`, `internal/formalcoverage`,
`cmd/formalcoverctl` and `rust/ws-driver` — `git diff --stat c738b81 HEAD` over
those paths is empty — so the cause is what `claude/us019-native-run` ADDS.

Measured cause, by regenerating the derived artifact in both worktrees and
diffing:

```
diff recon-main.json recon-mine.json
658a659 >   "autobahn_controls",
678a680 >   "autobahn_controls",
698a701 >   "autobahn_controls",
718a722 >   "autobahn_controls",
```

`claude/us019-native-run` adds the crate `rust/autobahn-controls` to the Rust
workspace. `assurance/formal/denominator-reconciliation.json` enumerates the
crate namespaces this plane ships, and was not refreshed. The same branch
regenerated `evidence/linkage/rust-identity-verification.json` (round 3 §1.4)
without refreshing the basis pin of it carried in
`evidence/formal/us023-coverage-report.json`, which is finding 4.3's stale
digest.

**NO DENOMINATOR MOVES.** Measured, because a corpus or denominator shift would
be a hard stop rather than a fix: regenerating changes 16 lines across three
files — four `"autobahn_controls"` insertions, four `detail` sentences that
recite the namespace list, and the artifacts' own self-referential digest and
git-blob pins. `obligations=24`, `proof_targets=10`, `denominator=24`,
`java_coverage=0/24`, `rust_coverage=0/24`, `paired_comparable_coverage=0/24`
and `refinement_coverage=0/24` are identical before and after.

**The regeneration was measured and then REVERTED; it is not committed here.**
It belongs to `claude/us019-native-run`'s own landing — that branch is red
standalone — and committing another track's derived US-023 artifacts from a
survivor-closure branch would make this branch's diff about something other than
what it claims.

**Owner/track action, exact:** on `claude/us019-native-run`, with
`VJWP_PROTECTED_STORE` exported, run `go run ./cmd/formalcoverctl reconcile -repo .`
then `go run ./cmd/formalcoverctl report -repo .`, and commit the three files
they rewrite. No code change is needed.

### 4.5 A `git worktree` does not get the pinned Java quarantine, and three packages go red for it

`.quarantine/` is gitignored and untracked at this head — `git ls-files -s .quarantine`
prints nothing, so round 3 §5.2's owner action has been done. The consequence is
that the pinned Java tree mainline commit `e1f3b89` recovered lives in ONE
worktree only. A fresh `git worktree add` gets an empty `.quarantine`, and
`internal/formalplan` and `internal/portplan` then fail with
`JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned HTTP 403`
— a diagnosis that reads as a network problem and is really a missing directory.

Demonstrated rather than argued, in three readings. `internal/formalplan` fails
identically in a detached worktree at pristine mainline `c738b81` (exit 1, 18
citations of `JAVA_SOURCE_UNAVAILABLE_OFFLINE`/`JAVA_QUARANTINE_UNAVAILABLE`),
so it is not this branch's. Then `.quarantine` was symlinked to the populated
one and both packages re-run:

- `internal/formalplan` — **`ok`, 408.629s, ZERO quarantine citations.** It is
  not a baseline failure at all; it is green here, which agrees with mainline
  `4ccf415` ("formalplan is green") and disagrees with round 3's §5.1, where it
  is listed among the declared baseline failures. **Round 3's baseline list is
  wrong on this package**, and the reason it looked right is this section.
- `internal/portplan` — stops citing the quarantine and fails instead for its
  DECLARED reason, `JAVAC_UNAVAILABLE: javac reports "... javac 21.0.10",
  pinned JDK is 17.0.19`, which is the `jdk_vendor` owner decision.
- `internal/lab` — unchanged, `PLATFORM_EXECUTOR_UNSUPPORTED ... CONTROLLED_CANARY
  requires Darwin sandbox-exec`.

So the declared baseline of exactly two environment failures is CORRECT, and it
only looks wrong from a worktree.

**RECOMMENDATION for anyone working in a worktree:**
`ln -sfn /home/user/verified-java-websocket-port/.quarantine .quarantine`
before reading the suite, or the baseline list will look wrong in a way that
costs an investigation. It cost one here.

---

## 5. Readings at this head

Every exit code below was read from the process that produced it.

| Command | Result |
| --- | --- |
| `go build ./...` | **exit 0** |
| `gofmt -l internal/autobahnsuite/` | **exit 0**, no file listed |
| `go vet ./internal/autobahnsuite/ ./cmd/autobahnsuitectl/` | **exit 0** |
| `make -C rust gates` (with `VJWP_PROTECTED_STORE` exported) | **exit 0** — `ac1-gates verdict=PASS gates_passed=8/8`, 9 `verdict=PASS`, 0 `verdict=FAIL`, 110 `test result: ok` |
| `make -C rust fixture-guard` (inside the gates run) | `result=PASS files=56 loops=332 violations=0 waivers=0 budget_waivers=0` |
| `go test -count=1 ./internal/autobahnsuite/ ./cmd/autobahnsuitectl/ ./internal/linkage/` | **exit 0** |
| `go test ./... -timeout 40m` | **exit 1**, 43 packages `ok`, 4 FAIL — see below |
| Baseline sweep, 110 sites, one `false && ( ... )` at a time | 40 RED, **70 GREEN**, 0 build-break |
| Same sweep with the probes in place | 104 RED, **6 GREEN**, 0 build-break |

`make -C rust gates` was first run WITHOUT `VJWP_PROTECTED_STORE` and refused, by
design, at `ledger-gates`: *"THE PROTECTED GOVERNANCE STORE IS NOT REACHABLE …
This is a REFUSAL, not a skip"* (exit 2). Recorded because a refusal that is
mistaken for a pass is exactly what that gate exists to prevent, and the first
reading of it here was a refusal.

`make -C rust gates` does NOT run the Go suite — not `internal/linkage`, not
`internal/formalplan`, not `internal/autobahnsuite`. Both were run and are read
separately above.

### 5.1 The four failing packages, each accounted for

Taken with `.quarantine` symlinked to the populated one (§4.5); without that
link the reading is six packages and two of them are the link, not the code.

| Package | Cause | Is it this branch's? |
| --- | --- | --- |
| `internal/lab` | `PLATFORM_EXECUTOR_UNSUPPORTED … CONTROLLED_CANARY requires Darwin sandbox-exec` | No — declared environment baseline |
| `internal/portplan` | `JAVAC_UNAVAILABLE: javac 21.0.10, pinned JDK is 17.0.19` | No — declared `jdk_vendor` owner decision |
| `internal/formalcoverage` | the `rust/autobahn-controls` crate is absent from the derived plane inventory (§4.4) | No — inherited from `claude/us019-native-run`, reproduced there standalone at exit 1, green on mainline `c738b81` at exit 0 |
| `cmd/formalcoverctl` | the same, one artifact downstream | No — same |

`internal/formalplan` is **`ok` (408.629s)** and is not on this list. Round 3
§5.1 lists it among the declared baseline failures; that is corrected in §4.5
with the reading that shows why.

Two packages fail for environment reasons and exactly two, as the baseline
declares. The third and fourth are one defect, it is named, its cause is
measured, its remedy is two commands, and it is not this branch's to apply.

---

## 6. What a reader should NOT conclude from this record

- **Not that `internal/autobahnsuite` is now fully covered.** 64 checks of one
  shape in four Go files gained a discriminating probe. The `switch` arms, the
  Rust-side checks and the conjuncts inside composite boolean expressions were
  never swept (§1.1). The floor moved; the ceiling is unmeasured.
- **Not that a closed check is a correct check.** A probe proves the check
  DISCRIMINATES — that some input distinguishes the guarded form from the
  unguarded one. It does not prove the check draws the line in the right place.
  `TestARunThatScoredNothingCannotSatisfyAC3` proves the empty-run guard is load
  bearing; it does not prove `Executed == 0` is the right threshold.
- **Not that this branch is landable.** The BLOCK from independent review
  `01a04961` on the US-019 work is untouched here, and finding 7's residual
  (the pinned Autobahn archive answering HTTP 403) is unchanged and still needs
  the owner action round 3 named.
- **Not that the Java leg was taken.** It was not. No AWS run, no benchmark run
  and no Autobahn re-run was triggered; the readings above are Go and Rust
  toolchain readings in this container only.

## 7. Owner actions this round leaves

1. **On `claude/us019-native-run`** (§4.4): export `VJWP_PROTECTED_STORE`, run
   `go run ./cmd/formalcoverctl reconcile -repo .` then
   `go run ./cmd/formalcoverctl report -repo .`, commit the three rewritten
   files. Measured to move no denominator. That branch is red standalone until
   it is done.
2. **Unchanged from round 3** (§4 of that record): make the pinned Autobahn
   source archive available in the quarantine. `ParsePinnedAutobahnRegistryArchive`
   already exists; the pinned URL answers HTTP 403 and the pinned commit/tree
   objects belong to a third-party repository this container does not have.
3. **Decide the four unreachable-check dispositions** in §3.1-3.4: the
   compile-time assertion for `independence.go:108`, the deletion of
   `baseline.go:201`, and the hoisted read that removes `suite.go:312`. All three
   are production edits on a branch under BLOCK and were not applied here.
