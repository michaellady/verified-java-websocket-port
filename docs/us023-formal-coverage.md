# US-023 formal coverage: reconciling two denominators, and reporting over the result

Status: OWNER_ATTESTED_NOT_INDEPENDENT; `independent_review_claimed: false`; production: false;
publication: false; signing: false.

This document defines what `assurance/formal/denominator-reconciliation.json`,
`assurance/formal/catalog-correction-proposal.json` and the two US-023 AC3 reports mean, how the
no-hiding rule is enforced mechanically rather than promised, and — as with every other document in
this programme — what none of it claims. Read section 6 before quoting any number.

## 1. The problem: two denominators, unreconciled

This repository carries **two** formal denominators, and until now nothing in the tree mapped either
onto the other.

| | size | what it names |
| --- | ---: | --- |
| `assurance/formal/obligation-catalog.json` | **24 obligations** | one language-neutral semantic obligation per row, each with a Java production symbol and a Rust production symbol |
| `assurance/formal/proof-targets.json` | **10 targets**, 11 property-claim references, 21 planned production symbols, 98 migration bindings | US-006's lane-A plan: Java authority spans by file and line, planned Rust symbols, and the conformance/differential invocation contract |

Master US-008 counts against the 24. US-023 AC3 requires a formal-coverage report over "a
language-neutral semantic-obligation denominator". A coverage report computed over an unreconciled
denominator is a number without a meaning: it cannot say whether the ten targets and the twenty-four
obligations describe the same programme, overlapping programmes, or two different ones.

## 2. The join, and why it is the only honest one

Both documents are anchored to the **same** digest-pinned Java-WebSocket 1.6.0 archive,
`sha256:f44e7647…`. That shared anchor is what makes a join legitimate at all, and it is recorded in
the reconciliation as `shared_java_anchor`.

The join key is the pinned-Java construct key **`DeclaringType#memberName`**:

* on the catalog side, derived from `java_bindings[].production_symbol` (JVM-descriptor form);
* on the plan side, derived from `targets[].production_symbols[].java_authority_members[]`
  (`package.Type#member(Params)` form, sometimes with trailing prose such as "masking XOR loop",
  which is dropped rather than parsed).

**The parameter list is deliberately not part of the key.** `docs/java-formal-binding-design.md`
section 3.2 already establishes that several of the catalog's JVM descriptors disagree with the
pinned source's actual parameter lists — `translateSingleFrame` returns `Framedata`, not `List`;
`processFrameContinuousAndNonFin` takes `(WebSocketImpl, Framedata, Opcode)`, not
`(Framedata, WebSocketImpl)`. Joining on a field known to be wrong would produce a smaller mapping
and a falsely confident one. This is the same binding key `internal/javabind` resolves against, so
the reconciliation and the Java binding lane cannot mean different things by "the same symbol".

**The Rust symbols are not a join key and are not used as one.** Not because it would be
inconvenient, but because they do not join: see section 4.

The mapping is computed by `internal/formalcoverage.Reconcile` and re-derived by
`TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive`. `TestTheJoinAgreesWithAnIndependentlyWrittenJoin`
recomputes both key sets with a **second, separately written** normaliser, so the artifact is not
merely agreeing with itself.

## 3. What the reconciliation exposed

| | |
| --- | ---: |
| Obligations mapped onto at least one proof target | 11 / 24 |
| **Obligations that map onto no planned proof target** | **13 / 24** |
| Proof targets named by at least one obligation | 6 / 10 |
| **Proof targets named by no obligation** | **4 / 10** |
| Distinct Java keys: catalog / plan / in both | 15 / 27 / **5** |

Five of the fifteen Java constructs the catalog names appear anywhere in the proof-target plan's
Java authority. Twenty-two of the plan's twenty-seven appear in no obligation. Both lists are
published by name in the artifact — `java_keys_in_both`, `java_keys_catalog_only`,
`java_keys_proof_target_only`, and the per-row `mapping_state` — because a count with no list is
exactly the shape in which the interesting case gets rounded away.

The four targets no obligation names are `target.formal.control.payload-length-bound`,
`target.formal.connection.no-terminal-escape`, `target.formal.messages.utf8-validation-total` and
`target.formal.concurrency.no-data-race`. Two of those four are precisely where the catalog
correction proposal points, which is a real result and not a coincidence: correcting
`surface.control.ping-pong` to `Draft_6455#processFrame` and `surface.messages.text-utf8` toward
`Charsetfunctions#stringUtf8` would map both onto targets that today nothing names.

### 3.1 The catalog's own declared basis has drifted

The catalog declares five `denominator_basis` entries with sha256 and git blob ids — the documents
its denominator was derived from. The reconciliation compares each against the file on disk. **Four
of the five no longer match**, including `assurance/formal/proof-targets.json` itself
(declared `sha256:fa75348c…`, on disk `sha256:bad1e069…`) and `corpora/frame/codec.json`, which
exists in no tree. The one that matches, `assurance/developer-tools/port-seam-dossier.json`, is a
705-byte placeholder declaring a single seam; the substantive dossier lives at
`evidence/intake/port-seam-dossier.json` and is not what the catalog pins.

A pin nothing compares is decoration. These four were never compared before, and are now.

## 4. The catalog's Rust column

All 24 `rust_bindings` rows declare source paths that exist in **no tree in this repository**
(`rust/connection-core/src/frame/decode.rs`, `rust/connection-core/src/connection.rs`,
`rust/connection-core/src/frame/mask.rs`, `rust/websocket-driver/src/lib.rs`) and symbols in the
crate namespaces `websocket_core::` and `websocket_driver::`, which the workspace does not ship —
the owner crate-naming decision fixed the namespace as `ws_core`, and the shipped crates are
`candidate_stub`, `gates`, `ws_core`, `ws_driver`, `ws_oracle_harness`, `ws_testee`.

This is the same defect class the catalog's Java column has, one degree worse: the Java column at
least names constructs that exist. It is checked mechanically — the reconciliation stats every
declared path and compares every namespace root against the crates the workspace actually ships —
and it is reported as a **denominator defect**, not as an uncovered obligation, because those are
different things.

The catalog's own `coverage` rows already say `rust_status: BLOCKED` for all 24, with
`execution_state: NOT_EXECUTED`, `observed_strength: NONE` and `tool: {name: kani, version:
"unavailable"}`. **The Rust coverage this repository can compute from its own pinned catalog is
0/24.** Any larger figure quoted elsewhere has no artifact in this tree.

## 5. The five mis-declared obligations

`assurance/formal/catalog-correction-proposal.json` diagnoses the five obligations declared against
Java symbols that cannot carry them, each against the digest-pinned source.

| obligation | catalog declares | defect | proposed |
| --- | --- | --- | --- |
| `obligation.mask-equation` | `Charsetfunctions.utf8Bytes` | `CATALOG_SYMBOL_SCOPE_MISMATCH` | chain: `Draft_6455#createByteBufferFromFramedata` + `Draft_6455#translateSingleFrame` |
| `obligation.mask-involution` | `Charsetfunctions.utf8Bytes` | `CATALOG_SYMBOL_SCOPE_MISMATCH` | same two-member chain |
| `surface.control.ping-pong` | `WebSocketAdapter.onWebsocketPing` | `CATALOG_SYMBOL_NOT_ON_EXECUTED_PATH` | `Draft_6455#processFrame` |
| `surface.messages.binary` | `WebSocketListener.onWebsocketMessage(…ByteBuffer)` | `INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE` | `Draft_6455#processFrameBinary` |
| `surface.messages.text-utf8` | `WebSocketListener.onWebsocketMessage(…String)` | `INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE` | `Draft_6455#processFrameText`, with `Charsetfunctions#stringUtf8(ByteBuffer)` as the validation authority |

Four of the five proposed constructs are **corroborated by the in-repo US-006 proof-target plan**,
which already names exactly those Java authority members for its planned Rust symbols. That matters:
the correction is not this branch's taste, it is the catalog's Java column disagreeing with the
other in-repo document that describes the same code. The fifth, `processFrameBinary`, is
corroborated by the pinned source alone and is labelled `PINNED_SOURCE_ONLY`.

**No correction claims it would connect its obligation.** The `would_bind` vocabulary admits only
`PARTIAL_AT_BEST` and `STILL_UNBINDABLE_THROUGH_THE_CURRENT_ADAPTER`, and a correction claiming
otherwise is refused by `EFFECT_VOCABULARY_IS_CLOSED_AND_CLAIMS_NO_CONNECTION`. Every correction
states its own `residual_gap`.

### 5.1 Why the catalog is not edited, and why that constraint is right

The catalog is vendored byte-identically from the read-only Codex plane;
`internal/javabind`'s tests assert its sha256 (`21112518…cdf59`) and its git blob id
(`be929320…97d2b`), and `internal/formalcoverage`'s tests assert both again so this package does not
depend on another package's test still existing. The corrections therefore live in a separate,
checked document, and the vendored bytes are untouched. The proposal argues the constraint rather
than merely obeying it:

* **A denominator either plane can edit stops being a denominator.** Two planes measure against
  these 24 rows precisely so their results are comparable. If either could repair it, every number
  computed from it would be a number about that plane's own opinion.
* **The defects are findings.** Repairing them in place deletes the evidence that they were ever
  there, and the standing count improves with no new observation of any program. A correction that
  erases its own justification is not a correction.
* **Byte equality is the only drift detector a vendored artifact has.** A repaired catalog would
  match no digest on the plane it came from and could not be told apart from a corrupted one.
* **Adoption has a blast radius this branch cannot see.** Changing a declared symbol changes which
  obligations map onto which targets, which mutants are obligation-specific, and what the Rust side
  must bind to. Proposing is in scope; deciding is not.

### 5.2 Two lanes

Following the `oraclee2e` / `javabinde2e` idiom already established here:

**Default lane** (`go test ./internal/formalcoverage/`). No quarantined tree required. Checks that
the proposal quotes the catalog's obligation statements and production symbols byte for byte; that
its defect classes are exactly the typed reasons `assurance/formal/java-binding-spec.json` already
recorded; that every `java_key` is derived from its own symbol; that every corroboration label is
**exact in both directions**; that every projected target and target symbol exists in the plan; and
that the catalog on disk is still the vendored bytes.

**Executed lane** (`-tags formalcovere2e`, `FORMALCOVER_E2E_JAVA_SOURCE_ROOT` set to the pinned
tree). Recomputes every cited file digest, re-resolves every proposed construct and compares line
numbers, byte spans, span digests and structure fingerprints; requires every member marked
unbindable to actually be refused by the resolver and every member marked bindable to actually
resolve; re-establishes the mask defect by scanning the condemned span for an XOR operator and the
proposed spans for the XOR and its `% 4` offset; and re-establishes the ping-pong defect against
this laboratory's own `OracleListener`, which is checked in rather than pinned and could otherwise
invalidate the finding silently.

## 6. The AC3 reports, and how the no-hiding rule is enforced

`evidence/formal/us023-coverage-report.json` is the canonical machine-readable report;
`evidence/formal/us023-coverage-report.md` is the human-readable coverage-style report, rendered as
a **pure function of the same derived value**, so the two cannot disagree.

Ten axes are reported, each an unweighted count of named obligations:

| axis | | coverage? |
| --- | ---: | --- |
| `java_coverage` | 0/24 | coverage |
| `rust_coverage` | 0/24 | coverage |
| `paired_comparable_coverage` | 0/24 | coverage |
| `production_linkage_java` | **6/24** | NOT coverage |
| `production_linkage_rust` | 0/24 | NOT coverage |
| `refinement_coverage` | 0/24 | coverage |
| `bound_parity` | 0/24 | NOT coverage |
| `counterexample_sensitivity_java` | **6/24** | NOT coverage |
| `counterexample_sensitivity_rust` | 0/24 | NOT coverage |
| `aggregate` | 0/24 | coverage |

The rule "**no weighted aggregate may hide a blocking obligation**" is enforced three ways at once,
and eleven invariants are recomputed on every derivation. A violated invariant does not annotate the
report: `DeriveReport` returns an error and writes nothing.

| | |
| --- | --- |
| `NH1` | Every axis numerator equals the length of the obligation list it publishes. |
| `NH2` | On every axis, counted and blocking obligations partition the fixed 24 exactly once each. |
| `NH3` | No axis counts an obligation it also reports as blocking. |
| `NH4` | The aggregate is bounded above by every coverage axis and its members are a subset of every coverage axis's members — an intersection, not a weighted sum. |
| `NH5` | No axis applies any weight. |
| `NH6` | Every blocking obligation appears in `blocking_gaps` with at least one named reason, and nothing else does. |
| `NH7` | Any obligation below its required strength on either side is blocking. (This is AC3's own sentence, mechanised.) |
| `NH8` | The freeze verdict is BLOCKED exactly when at least one obligation blocks, and it names every one. |
| `NH9` | No non-coverage axis feeds the aggregate, and any non-zero non-coverage numerator says in the artifact that it is not coverage. |
| `NH10` | Exactly 24 rows over 24 distinct obligations. |
| `NH11` | While the plan records no resolver verification, the Rust production-linkage numerator, the resolver-verified planned-symbol count and the verified migration-binding count are all zero. |

The **evidence-strength lattice** is a total order over a closed vocabulary, and an unranked label
is an error rather than a pass. That is the cheapest attack on a coverage number — invent a strength
nobody ranked — and an unranked label that compared as "not less than required" would silently
discharge all 24 obligations. `EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY` ranks strictly below
`PRODUCTION_REFINEMENT`, so the Java lane's own honest label cannot discharge the catalog.

`RETAINED_KILLED_DIFFERENT_SUBJECT` — the disposition all 24 catalog mutation records carry — is
deliberately **not** counted as counterexample sensitivity. A mutant killed by some other
obligation's evidence is not sensitivity for this one, and counting it would be the purest form of
the round-up these reports exist to prevent.

### 6.1 Exit codes

`go run ./cmd/formalcoverctl verify -repo .` recomputes all three artifacts and compares them
against the retained bytes; it prints the honest numbers **before** failing. `freeze-gate` derives
the report fresh — it never reads the retained one, so a hand-edited artifact cannot open the gate.

| command | exit | meaning |
| --- | ---: | --- |
| `reconcile`, `report`, `verify` | 0 | the retained artifacts are what the evidence derives |
| any subcommand | 1 | the tool failed, or verification found drift |
| `freeze-gate` | **2** | a well-formed report whose verdict is BLOCKED |

1 and 2 are distinct on purpose: collapsing them would let a broken tool read as a blocked freeze,
or the reverse.

## 7. The resolver ceiling

`proof-targets.json` reads all 21 planned production symbols as `PLANNED_PENDING_RESOLVER` with
`resolved_symbol: null`, all 98 migration bindings `rust_identity_verified: false`,
`resolver_verified_at: null`, state `RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED`, planned resolver
`rust-analyzer`. The strongest linkage evidence this repository holds,
`evidence/linkage/rust-identity-verification.json`, resolves 45 of 47 rows by a deterministic
declaration scan and labels its own strength *"declaration-scan (reviewed-glancer class), not
rust-analyzer semantic resolution"*.

The two documents do not contradict each other and neither overstates itself. The ceiling is the
**conjunction** of what they honestly say:

> **No formal obligation in this repository binds to a resolver-verified shipped Rust symbol: 0/24.**
> Every claim that formal evidence here reaches shipped Rust rests on a declaration scan, not on
> semantic resolution.

That sentence is derived into the report's `resolver_ceiling` block, quotes the overlay's own
strength label verbatim, and appears in the rendered report as its own section. `NH11` makes it
structural rather than editorial: flipping `rust_identity_verified` on one migration binding, or
marking one planned symbol `RESOLVER_VERIFIED`, without the plan recording a resolver run does not
produce a slightly better number — it produces **no report at all**.

## 8. What this is NOT

This section is normative for anything that quotes this work.

* **Nothing here is a proof, and nothing here executes one.** No prover, model checker or abstract
  interpreter is applied to anything. These artifacts read evidence that already exists and report
  what it says.
* **A mapping is not coverage.** That an obligation maps onto a proof target says only that both
  documents name the same pinned-Java construct. It says nothing about whether any proof exists, was
  executed, or reaches the required strength. Every one of the ten targets is a *plan*.
* **The non-zero numerators are not coverage.** `production_linkage_java` = 6/24 and
  `counterexample_sensitivity_java` = 6/24 are attribution facts, quoted from
  `internal/javabind`'s projection. They are labelled `NOT COVERAGE` in both artifacts, excluded from
  the aggregate by construction, and a reader who quotes one as coverage is quoting it against the
  artifact.
* **Zero coverage is not a claim that the programs are wrong.** It is a claim about what evidence
  exists at what strength, over a denominator that is itself defective on both sides.
* **The corrections are not adopted, and adopting them would not connect anything.** Not one
  proposed symbol has been bound, observed or mutation-tested by this work. The spans and
  fingerprints are resolutions of pinned source, not evidence about behaviour.
* **The reconciliation does not repair either document.** It publishes their disagreement. The
  catalog is untouched; the proof-target plan is untouched.
* **This is not independent.** Owner-executed on a single Linux host in one session,
  `OWNER_ATTESTED_NOT_INDEPENDENT`, `independent_review_claimed: false`.
* **This changes no behaviour-bearing code.** No Java, no Rust, no adapter and no existing evidence
  artifact is modified. The differential, handshake and concurrency surfaces cannot have moved.

## 9. Attribution

The immutable 24-obligation catalog and its schema are the Codex plane's work, vendored here
unmodified; `internal/javabind`, its projection and its receipt are pre-existing project work,
quoted rather than recomputed; `assurance/formal/proof-targets.json` is US-006's; the Rust identity
overlay is the linkage track's. This work adds the mapping between them, the correction proposal,
and the two reports.
