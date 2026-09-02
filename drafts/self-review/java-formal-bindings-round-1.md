# Self-review round 1 — Java formal bindings

Branch: `claude/java-formal-bindings`, based on `claude/feature/verified-java-websocket-port` at
`01ee5159e8765ce42d28e0873a909288ca7246ef` (rebased from `8a7f713` onto mainline mid-round to pick
up the F004 concurrency-test fix; see section 6).
Reviewed: 2026-09-02.
Assurance: OWNER_ATTESTED_NOT_INDEPENDENT; `independent_review_claimed: false`; production: false;
publication: false; signing: false.

This is a self-review by the author of the work. It is not an independent review and must not be
counted as one.

## 1. The result under review

`javabindctl verify -repo .` derives, from `assurance/formal/java-binding-spec.json`,
`assurance/formal/obligation-catalog.json` and `evidence/java/formal-bindings/receipt.json`:

```
catalog=us023-formal-obligations denominator=24
java_bindings_connected=4/24
java_bindings_partial=2/24
java_bindings_disconnected=18/24
java_mutation_sensitive=6/24
java_bindings_at_required_strength=0/24
refinement=0/24
aggregate=0/24
```

Clause-level: 9 of 11 declared clauses satisfied; 10 of 10 declared canaries killed.

## 2. The trap this repository has been bitten by, hunted explicitly

> *a binding that is satisfied by the existence of a file rather than by the identity of its content*

This is the failure the standing 0/24 Java count is itself an instance of: the catalog's own 24
`java_bindings` entries name a `source_path` that exists nowhere, and give all 24 the same
`source_sha256` — the digest of the whole source archive. Nothing there distinguishes one obligation
from another, or one method from the file it lives in.

Where the trap could have reappeared in this work, and what was done:

| Where existence could have stood in for identity | What is checked instead |
| --- | --- |
| The catalog file at its path | Its sha256 **and** its Git blob id are asserted in a test; the spec pins the sha256; `Derive` refuses when the catalog on disk is not the pinned bytes. Attack A2 (one appended space) and A3 (same path, same 24 obligations, one statement reworded) are both refused. |
| The pinned Java file at its path | The receipt records the file sha256 **and** the byte span **and** the span sha256 **and** a whitespace-insensitive structure fingerprint of the bound declaration. The `javabinde2e` lane recomputes all of them from the tree. |
| "A mutation exists" | The canary is stored as offset + length + **sha256 of the bytes it removes**. `ApplyMutation` refuses to splice when those bytes do not hash to the recorded value, and refuses an offset outside the bound span (attack A12). |
| "A mutant run exists" | The mutant's response must bind the digest of the archive the Go side built for it. Attack B13 — copying the baseline response over the mutant's, so the canary appears to survive — is refused because the response then binds the pinned runtime rather than the mutant archive. |
| "A control run exists" | The control must reproduce the baseline's semantic projection exactly. Attacks C8 (control made to diverge) and C14 (control deleted) both drop the derived numerator from 4 to 3. |
| "A coverage file exists with a number in it" | The number is derived. Attack A5 (typing 24 into the numerator) is refused; attacks C7/C9 show the derived number moving to 3 when evidence is removed. |

One residual instance is disclosed rather than closed: in the **self-contained lane** the pinned
Java source spans are provenance recorded in the receipt, not recomputed, because the quarantined
tree is deliberately not in Git. Only the `javabinde2e` lane recomputes them. Section 5 of the
design document states this; it is a real bound on the default-lane claim.

## 3. Deletion attacks actually run

Every attack was executed against disposable copies; the exit code was read from the process. `A*`
attacks ran before the verifier printed derived counts on mismatch; `B*`/`C*` re-ran the interesting
ones after that, and after rebinding the receipt to the edited spec so the *semantic* rule had to
fire rather than the spec-digest binding.

| # | Attack | Result |
| --- | --- | --- |
| A0 | Untouched copy | exit 0, 4/24 — the control for the attacks themselves |
| A1 | Delete the immutable catalog | exit 1, file not found |
| A2 | Append one whitespace byte to the catalog | exit 1, "the catalog on disk is not the catalog the spec pins" |
| A3 | Same path, same 24 obligations, one statement reworded | exit 1, same refusal — content, not shape |
| A4 | Delete the receipt | exit 1, file not found |
| A5 | Type `24` into `java_bindings_connected` | exit 1, "not what the retained evidence derives" |
| A6 | Edit one retained baseline response, leave its digest | exit 1, digest recomputation names the run |
| A7 | Delete one mutant run | exit 1 |
| A8 | Make one control diverge (digest kept consistent) | exit 1 |
| A9 | Remove one clause canary from the spec | exit 1 (spec-digest binding fired first → re-run as C9) |
| A10 | Rebind an obligation to a symbol the catalog does not name | exit 1 (→ re-run as B10) |
| A11 | Drop one obligation from the denominator | exit 1 (→ re-run as B11) |
| A12 | Move a canary outside its declaration span | exit 1, "lands outside the bound span [7852,8815)" |
| B10 | A10 with the receipt rebound to the edited spec | exit 1, the semantic rule fires: "echoes symbol … but the catalog declares …" |
| B11 | A11 with the receipt rebound | exit 1, "obligation \"surface.websocket-open\" is neither bound nor given a typed unbound reason" |
| B13 | Copy the baseline response over the mutant response so the canary appears to survive | exit 1, "response binds runtime … not the expected …" |
| C9 | Remove the only clause canary of `obligation.preallocation-cap` | exit 1, **derived 3/24** |
| C7 | Delete one mutant run | exit 1, **derived 3/24** |
| C8 | Make one control diverge from its baseline | exit 1, **derived 3/24**, partial 3/24 |
| C14 | Delete one control run | exit 1, **derived 3/24**, partial 3/24 |

The C-series is the important one: the numerator *moves with the evidence*. 4 is a measurement, not
a string.

In-test deletion attacks (`internal/javabind/coverage_test.go`, `cmd/javabindctl/main_test.go`) cover
the same ground in the default lane: tampered response line, tampered pinned-runtime binding,
inflated numerator, substituted catalog, wrong removed-bytes digest, out-of-span offset, unknown
predicate kind. Each was confirmed to fail by running it against the untampered artifacts first.

## 4. Over-claims hunted

**Claim vocabulary.** `grep -ri "formally verified\|1:1\|absolutely correct"` over everything this
branch adds returns only the *disclaimers* — the design document's section 7 and the projection's
`not_claims` array, both of which use the phrase to say it does not apply. The word "proof" appears
in this work only in the negative or when describing the Rust/Kani side, which this work does not
touch.

**Strength.** Every binding carries `observed_strength:
EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY` against `required_strength: PRODUCTION_REFINEMENT`.
`java_bindings_at_required_strength` is a separate numerator and is 0/24. A test asserts no
obligation row sets `meets_required_strength`, and that refinement and aggregate stay 0.

**Corrected over-claims, found during the work:**

1. *One canary per obligation was not enough.* The first design gave each obligation a single
   canary, and clause satisfaction depended only on witnesses holding. That would have counted
   `obligation.control-fin-and-length` as fully bound: both its clauses' witnesses hold against the
   pinned Java. But the 125-octet bound is implemented in `Draft_6455.translateSingleFramePayloadLength`,
   not in `ControlFrame.isValid`, which is the symbol the catalog names. The design was changed to
   require a canary **per clause**; that obligation is now correctly PARTIAL. Without the change the
   headline would have read 5/24 and one of the five would have been wrong.
2. *A predicate written from expectation rather than observation.* The first
   `checked-header-arithmetic` clause asserted `consumed_bytes == 0`; the pinned Java actually
   consumes all seven bytes into its own buffer. The witness failed, the obligation showed
   DISCONNECTED, and the predicate was rewritten to say what the clause actually means (nothing
   delivered, everything still buffered). The failure was the machinery working: an unexamined guess
   did not quietly pass.
3. *The Java side of `surface.close.status-code` does not do what its third clause asserts.* Its
   invalid-UTF-8 reason clause fails: the pinned runtime answers with a `NullPointerException`-class
   rejection and no close code, not a typed 1007. The clause was kept and the obligation reported
   PARTIAL rather than the clause being deleted or reworded to match observed behaviour.
4. *Novelty was nearly claimed for two findings that were already ledgered.* Both the role-masking
   gap and the invalid-UTF-8 close-reason behaviour are already recorded in
   `evidence/java/behavior-delta-ledger.json` at sequences 18 and 32. This was checked before the
   proposal was written; `drafts/ledger-proposals/java-formal-binding-corroborations.json` therefore
   proposes no record and states plainly that it corroborates rather than discovers.

**Attribution.** The 24-obligation catalog and its schema are the Codex plane's artifacts, vendored
byte-identically with their Git blob ids recorded and asserted. Nothing on any `codex/*` branch was
written. The `java-oracle` adapter, the pinned intake and the `oraclee2e` two-lane idiom are
pre-existing project work, reused unchanged.

## 5. Weaknesses I can see and am not hiding

1. **The default lane does not recompute Java source spans.** Stated in section 5 of the design.
   Closing it would require either vendoring upstream source (which intake policy forbids) or making
   `go test ./...` depend on the quarantined tree (which would make the suite unrunnable without it).
2. **The mutant driver is a second entry point.** `MutantOracleMain` is not `OracleMain`. It
   delegates to `OracleMain.run`, so the protocol and engine code is identical, and the control runs
   are precisely the check that this substitution does not move the observation — but the two mains
   are not literally the same class, and a reviewer should look at
   `assurance/formal/java-binding/MutantOracleMain.java` and satisfy themselves it adds no behaviour
   beyond a digest check. It is 80 lines.
3. **Scenario sets are small.** Between one and three scenarios per obligation. The claim is
   explicitly non-exhaustive and the projection says so, but "the pinned Java did this on these
   inputs" is a weaker statement than a reader may take "binding" to imply.
4. **Clause decompositions are mine.** The decomposition of an English catalog statement into
   clauses is a judgement, written down and reviewable, but a different reviewer might decompose
   `surface.framing.masking` or `surface.errors.protocol-fault` differently and get a different
   count. The decompositions are in the spec, in full, for exactly that reason.
5. **Four is a small number.** 4/24 is 17% of the denominator. Eight further obligations look
   reachable (section 8 of the design lists them with reasons); five are blocked by catalog defects
   that cannot be repaired here; three are not observable through this adapter at any strength.
6. **`obligation.preallocation-cap` and `surface.limits.allocation` share a witness.** Only the
   former is credited. That is the conservative choice, but it does mean the count is depressed by a
   deliberate refusal to double-credit rather than by an absence of evidence.
7. **Single host, single session, one operator.** Nothing here is independent, reproduced on a
   second host, or reviewed by anyone else.

## 6. Things I checked that came back clean

* `git status --porcelain` shows only untracked additions: not one tracked file in the repository is
  modified by this branch, so no Rust at all — production or test — was touched. The Rust proof and
  mutation numerators, the differential evidence and the exam surface therefore cannot have moved,
  and the Rust gates remain directly comparable to mainline's.
* `make -C rust gates` reads `gates_passed=8/8`, exit 0, on this branch. An earlier run failed
  `a_producer_racing_the_owner_drop_never_blocks_and_never_reports_a_stale_accept`; that is the
  known host-speed flake filed as F004 (an iteration-count spin bound sized to a host), it was
  reproduced with `rust/` byte-identical to mainline, and the fix landed on mainline at `01ee515`
  independently of this work. The branch was rebased onto that commit rather than the fix being
  re-derived here.
* `evidence/java/behavior-delta-ledger.json` is unmodified; the proposal lives under
  `drafts/ledger-proposals/`.
* No retained receipt outside this lane was edited, and no evidence was re-baselined.
* No test was skipped, disabled or quarantined. The `javabinde2e` lane is a build-tagged additional
  lane, following the repository's existing `oraclee2e` pattern; it does not replace or weaken the
  default lane.
* `java-oracle`'s runtime digest pin was not relaxed, edited or bypassed. Baselines still run through
  it. This was the first thing I tried to do when the pin blocked the mutant lane, and it was the
  wrong thing to do.
* The `javabinde2e` lane re-executes all 30 runs and reproduces the retained receipt byte for byte,
  so the evidence is deterministic on this host.
* `go build ./...` exits 0. `go test -count=1 -timeout 40m ./...` exits 1 with exactly two failing
  packages, both the known Linux-environment ones and both failing identically before this branch
  added anything: `internal/lab`
  (`TestControlledCanaryRequestIsClosedAndRequiresAuthenticatedPromotions`, Darwin `sandbox-exec`)
  and `internal/portplan` (`TestDeriveReproducesCommittedEvidence`, vendor-bound). No other package
  fails.
* One validation nuance worth passing on, unrelated to this work: with Go's default per-package
  timeout of 600s, `internal/benchplan` and `internal/formalplan` time out on this host under any
  concurrent load — `internal/benchplan` needs about 623s even when run alone. They pass with
  `-timeout 40m`. A bare `go test -count=1 ./...` on a busy host will report those two as failures
  that are neither assertion failures nor regressions.
