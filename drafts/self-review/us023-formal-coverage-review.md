# Self-review — `claude/us023-formal-coverage`

Recorded from tool output on this branch. Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`,
`independent_review_claimed: false`. Nothing here was independently reviewed and nothing here is a
proof.

## What this branch was asked to do, and what it did

Three connected problems from the criteria audit (findings 7 and 9): two unreconciled denominators;
five obligations declared against Java symbols that cannot carry them; and AC3's two reports not
existing. Plus one thing to carry forward whether or not it helped the numbers: the resolver
ceiling.

**All additions. Zero modifications, zero deletions of tracked files.** `git status` shows six new
paths and no `M` line; the vendored catalog still hashes to
`21112518f48443b4e20ecae537bed72b8c9e19167ad00bc6f325bff9374cdf59`. No behaviour-bearing byte moved,
so the differential, handshake and concurrency surfaces cannot have shifted by this branch.
`evidence/java/behavior-delta-ledger.json`, `internal/deltaledger` and
`assurance/concurrency/results.json` were read and never written.

## 1. The reconciliation, and what it exposed

`assurance/formal/denominator-reconciliation.json`, derived by
`internal/formalcoverage.Reconcile`, joined on the pinned-Java construct key
`DeclaringType#memberName` — the one key both documents carry, both anchored to the same archive
digest `sha256:f44e7647…`.

```
obligations=24 proof_targets=10
obligations_mapped_to_a_target=11/24
obligations_with_no_target=13/24
targets_named_by_an_obligation=6/10
targets_with_no_obligation=4/10
java_keys catalog=15 proof_targets=27 both=5 catalog_only=10 target_only=22
catalog_rust_binding_rows_with_absent_source_path=24/24
```

**Obligations with no proof target — 13, named:** `obligation.control-fin-and-length`,
`obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`,
`surface.close.status-code`, `surface.concurrency.command-order`, `surface.control.ping-pong`,
`surface.errors.protocol-fault`, `surface.framing.masking`, `surface.handshake.client-request`,
`surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`.

**Targets no obligation names — 4:** `target.formal.concurrency.no-data-race`,
`target.formal.connection.no-terminal-escape`, `target.formal.control.payload-length-bound`,
`target.formal.messages.utf8-validation-total`.

Three further findings the join produced, none of which I went looking for:

* **Seven obligations collapse onto one construct.** `Draft_6455#translateSingleFrame` carries
  `obligation.checked-header-arithmetic`, `length-canonical-16`, `length-canonical-64-high-bit-zero`,
  `preallocation-cap`, `role-masking`, `surface.framing.frame-octets` and
  `surface.limits.allocation`. Twenty-four obligations are distinguished by fifteen Java keys, one of
  which carries seven. Combined with the one archive-level `source_sha256` shared by all 24, the
  catalog's Java column does not distinguish most of its own rows by content **or** by name.
* **Four of the catalog's five declared `denominator_basis` pins have drifted.**
  `assurance/formal/proof-targets.json` is pinned at `sha256:fa75348c…` and is `sha256:bad1e069…` on
  disk; `evidence/intake/compatibility-surface.json` and
  `evidence/intake/semantic-id-migration-map.json` likewise; `corpora/frame/codec.json` exists in no
  tree. The one that matches, `assurance/developer-tools/port-seam-dossier.json`, is a 705-byte
  placeholder with one seam — the substantive dossier is at `evidence/intake/port-seam-dossier.json`
  and is not what the catalog pins. **These pins had never been compared before.**
* **The catalog's Rust column is worse than its Java column.** All 24 `rust_bindings` declare source
  paths that exist in no tree and namespaces (`websocket_core::`, `websocket_driver::`) the
  workspace does not ship — the owner crate-naming decision fixed `ws_core`. Checked mechanically by
  statting each path and comparing each namespace root against the crates the workspace actually has.

I also read the catalog's own `coverage` and `evidence` rows rather than taking a figure on report:
**all 24 read `rust_status: BLOCKED`, `execution_state: NOT_EXECUTED`, `observed_strength: NONE`,
`tool: {name: kani, version: "unavailable"}`.** `docs/java-formal-binding-design.md` says the Codex
plane drove Rust coverage to 19/24. That number has **no artifact in this repository**; the Rust
coverage computable from the pinned catalog is 0/24, and the report says so.

The join is checked against a **second, independently written** normaliser
(`TestTheJoinAgreesWithAnIndependentlyWrittenJoin`), so the artifact is not merely agreeing with
itself.

## 2. The five corrections, with Java citations

`assurance/formal/catalog-correction-proposal.json`. Every line number, byte span, span digest and
structure fingerprint below was read out of
`.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/` through
`internal/javabind`'s own resolver, and is recomputed from that tree again by the `formalcovere2e`
lane.

### C1/C2 — `obligation.mask-equation`, `obligation.mask-involution`

Declared against `org.java_websocket.util.Charsetfunctions.utf8Bytes(Ljava/lang/String;)[B`.

`src/main/java/org/java_websocket/util/Charsetfunctions.java:49-51`, span
`sha256:e76611df…`, 93 bytes:

```java
public static byte[] utf8Bytes(String s) {
  return s.getBytes(StandardCharsets.UTF_8);
}
```

No XOR, no mask key, no offset. The e2e lane scans the span for `^`, `mask` and `Mask` and fails if
any appears.

Proposed, a two-member chain in `Draft_6455.java` (file `sha256:39756c4b…`, pinned by BOTH
`proof-targets.json` and the javabind receipt):

* `Draft_6455#createByteBufferFromFramedata` — **478-526**, span `sha256:137f5cff…`. Line 513
  allocates the key; **line 516** is `buf.put((byte) (mes.get() ^ maskkey.get(i % 4)));` — the XOR
  and the `i % 4` offset in one expression.
* `Draft_6455#translateSingleFrame` — **528-597**, span `sha256:a469fed7…`. **Line 562** is
  `payload.put((byte) (buffer.get() ^ maskskey[i % 4]));` — the inverse.

Corroborated: `proof-targets.json`'s `sym.framing.apply-mask` names exactly those two members,
verbatim, including the qualifiers "masking XOR loop" / "unmasking XOR loop". The correction is not
my taste; it is the catalog disagreeing with the other in-repo document about the same code.

Residual gap, stated in the artifact: the receive-side clause becomes witnessable; the emit-side
does not, because line 513's key is `reuseableRandom.nextInt()` and the adapter omits emitted client
mask keys. Involution needs one observation spanning both applications, which a single-endpoint
adapter cannot produce. `PARTIAL_AT_BEST` and
`STILL_UNBINDABLE_THROUGH_THE_CURRENT_ADAPTER` respectively — neither claims a connection.

### C3 — `surface.control.ping-pong`

Declared against `WebSocketAdapter.onWebsocketPing(WebSocket,Framedata)`.
`WebSocketAdapter.java:83-86`, span `sha256:d7dffbe3…`; class abstract at line 42; **line 85** is
`conn.sendFrame(new PongFrame((PingFrame) f));`.

The declaration is real and does implement the automatic pong. It is dead under this laboratory's
own adapter: `java-oracle/src/main/java/OracleEngine.java:777` declares
`OracleListener extends WebSocketAdapter`, and **lines 800-803** override `onWebsocketPing` with
`addControl("ping", frame);` and no `super` call. The e2e lane re-reads those lines and fails if
`super.onWebsocketPing` ever appears or the `extends` goes away.

Proposed: `Draft_6455#processFrame(WebSocketImpl,Framedata)` — **892-918**, span `sha256:3bbdfaab…`.
**898-899** route `Opcode.PING` to the listener with the received frame intact; **900-902** route
`Opcode.PONG`. Corroborated by `sym.control.process-frame`.

Residual gap: `processFrame` covers dispatch, not the ≤125 bound (that is
`translateSingleFramePayloadLength` **617-620** and `ControlFrame.isValid`, already the catalog's
symbol for `obligation.control-fin-and-length`, so crediting it here would double-count one
witness), and not the payload-preserving echo (`WebSocketAdapter:85` → `PongFrame:47-50`). Reaching
the echo needs the *adapter* to call `super.onWebsocketPing` — an adapter change that would move
existing retained oracle behaviour. **Not proposed.**

### C4 — `surface.messages.binary`

Declared against `WebSocketListener.onWebsocketMessage(WebSocket,ByteBuffer)`.
`WebSocketListener.java:45` is `public interface WebSocketListener {`; **line 92** and **line 100**
are the two `onWebsocketMessage` declarations, both body-less. Two defects: no implementation site,
and `declaringType#simpleName` is ambiguous. The resolver refuses it verbatim —
*"WebSocketListener declares 2 members named \"onWebsocketMessage\"; the binding key
declaringType#name is ambiguous"* — and the e2e lane requires that refusal to still happen.

Proposed: `Draft_6455#processFrameBinary` — **956-963**, span `sha256:54a6578f…`; **958-959** hand
`frame.getPayloadData()` to the listener with no copy. **This one is corroborated by the pinned
source alone** — `proof-targets.json` names no Java authority member for binary message delivery at
all — and is labelled `PINNED_SOURCE_ONLY`. Residual gap: fragmented-message exactness is decided in
`processFrameIsFin` (**999**), outside this span.

### C5 — `surface.messages.text-utf8`

Same interface defect on the `String` overload (**line 92**).

Proposed, two candidates, ranked and each labelled:

* `Draft_6455#processFrameText` — **982-990**, span `sha256:10392711…`; **985-986** call
  `Charsetfunctions.stringUtf8(frame.getPayloadData())`. **Bindable.**
* `Charsetfunctions#stringUtf8(ByteBuffer)` — **72-85**; **73-75** build a decoder with
  `CodingErrorAction.REPORT` (declared at **44**), **81-83** raise
  `InvalidDataException(CloseFrame.NO_UTF8)`. Corroborated by `sym.utf8.string-utf8`. **NOT bindable
  under the current resolver**: `Charsetfunctions` declares two members named `stringUtf8` (**68**
  `byte[]`, **72** `ByteBuffer`), so the key is ambiguous.

That second row is the point of ranking them. Adopting the *corroborated* symbol alone would leave
the obligation unbindable for a second, different reason, and the proposal says so rather than
letting the correction read as a fix.

### Why the catalog is not edited

The proposal is a separate file; the vendored bytes are untouched, and
`internal/formalcoverage` asserts the sha256 **and** the git blob id again rather than relying on
`internal/javabind`'s test still existing. The proposal argues the constraint in four points rather
than merely obeying it (a denominator either plane can edit stops being a denominator; the defects
are findings and repairing them deletes their own justification; byte equality is a vendored
artifact's only drift detector; adoption has a blast radius this branch cannot see).

**Scope stated, not left implicit.** Two further obligations carry catalog-defect reason codes that
this proposal does *not* correct — `surface.errors.protocol-fault` (declared against an exception
TYPE) and `surface.handshake.client-request` (declared against `WebSocketImpl.startHandshake`, which
the handshake oracle does not run). They are named in the proposal's `not_claims` so their absence
is a scope statement, not an oversight.

## 3. The two AC3 reports, and the no-hiding rule

`evidence/formal/us023-coverage-report.json` (canonical, machine-readable) and
`evidence/formal/us023-coverage-report.md` (human-readable, coverage-style). The Markdown is a
**pure function** of the same derived value — it reads no artifact and recomputes no number — so the
two cannot disagree.

Read from `go run ./cmd/formalcoverctl report -repo .`:

```
java_coverage=0/24 [coverage weighting=NONE]
rust_coverage=0/24 [coverage weighting=NONE]
paired_comparable_coverage=0/24 [coverage weighting=NONE]
production_linkage_java=6/24 [NOT_COVERAGE weighting=NONE]
production_linkage_rust=0/24 [NOT_COVERAGE weighting=NONE]
refinement_coverage=0/24 [coverage weighting=NONE]
bound_parity=0/24 [NOT_COVERAGE weighting=NONE]
counterexample_sensitivity_java=6/24 [NOT_COVERAGE weighting=NONE]
counterexample_sensitivity_rust=0/24 [NOT_COVERAGE weighting=NONE]
aggregate=0/24 [coverage weighting=NONE]
blocking_obligations=24/24
resolver_ceiling obligations_on_resolver_verified_rust=0/24 resolver_verified_at=null
  strongest_linkage="declaration-scan (reviewed-glancer class), not rust-analyzer semantic resolution"
```

Every coverage axis is zero. The only two non-zero numerators are attribution facts quoted from
`internal/javabind`'s projection, both printed on the same screen as the zeros and both labelled
`NOT_COVERAGE` — the discipline `javabindctl` already uses when it prints
`at_required_strength=0/24` beside `connected=4/24`.

**Enforcement is mechanical, in eleven invariants recomputed on every derivation.** A violated
invariant does not annotate the report: `DeriveReport` returns an error and writes nothing.

* `NH1` numerator == length of the published member list.
* `NH2` counted ∪ blocking partitions the fixed 24, exactly once each.
* `NH3` nothing is counted and blocked on the same axis (stated separately from NH2 so deleting
  either still catches it).
* `NH4` the aggregate is bounded above by every coverage axis and its members are a subset of every
  coverage axis's — an intersection, not a weighted sum.
* `NH5` no axis carries a weight.
* `NH6` every blocking obligation is in `blocking_gaps` with ≥1 named reason, and nothing else is.
* `NH7` **AC3's own sentence, mechanised**: below required strength on either side ⇒ blocking.
* `NH8` the verdict follows the blocking list, not the aggregate, and names every blocker.
* `NH9` no non-coverage axis feeds the aggregate, and a non-zero non-coverage numerator must say in
  the artifact that it is not coverage.
* `NH10` exactly 24 rows over 24 distinct obligations.
* `NH11` the resolver ceiling.

Two further structural refusals worth naming. The **strength lattice** is a total order over a
closed vocabulary and an unranked label is an *error*, not a pass — inventing a strength nobody
ranked is the cheapest attack on a coverage number. And
`RETAINED_KILLED_DIFFERENT_SUBJECT`, the disposition all 24 catalog mutation records carry, is
deliberately **not** counted as counterexample sensitivity: a mutant killed by another obligation's
evidence is not sensitivity for this one.

### Exit codes, read from the process (built binary, not `go run`)

```
formalcoverctl freeze-gate -repo .   exit 2   (BLOCKED, 24/24)
formalcoverctl verify      -repo .   exit 0
formalcoverctl report      -repo .   exit 0
formalcoverctl bogus       -repo .   exit 1
```

1 and 2 are distinct on purpose: collapsing them would let a broken tool read as a blocked freeze,
or the reverse. `freeze-gate` derives the report fresh and never reads the retained one, so a
hand-edited artifact cannot open the gate.

## 4. The resolver ceiling, made structural

The report carries a `resolver_ceiling` block deriving, not asserting:
`RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED`; planned resolver `rust-analyzer`;
`resolver_verified_at: null`; 21 planned production symbols, **0** resolver-verified; 98 migration
bindings, **0** `rust_identity_verified`; strongest overlay
`evidence/linkage/rust-identity-verification.json`, 45/47 rows by deterministic declaration scan,
its own declared strength *"declaration-scan (reviewed-glancer class), not rust-analyzer semantic
resolution"* quoted verbatim; and the derived line **0/24 obligations bound to a resolver-verified
shipped Rust symbol**.

`NH11` makes that structural rather than editorial. Flipping one migration binding's
`rust_identity_verified` to `true`, or marking one planned symbol `RESOLVER_VERIFIED`, without the
plan recording a resolver run does not produce a slightly better number — it produces **no report at
all**. Both attacks are tested
(`TestFlippingTheResolverCeilingInTheInputRefusesTheWholeReport`,
`TestMarkingAPlannedSymbolResolverVerifiedRefusesTheWholeReport`) and both assert the refusal names
`NH11` specifically, not merely that something failed.

## 5. RED readings and deletion attacks

The suite went green on its first run, which is not evidence of anything. **47 deletion attacks**
were then run: each check neutralised in turn, the suite re-run, the file restored and re-hashed to
confirm byte-identical restoration.

The first sweep was **invalid for the eleven invariants**: the mutation left `holds`/`detail`
unused and the package failed to *compile*. A build failure proves the mutation broke the file, not
that the check was load-bearing. The mutation was changed to `holds || true`, which keeps both
locals used and the package compiling, and the sweep re-run.

That first valid sweep found **11 checks that stayed green when deleted**. Rather than record them
as decoration, an attack test was written for each; the second sweep found six more and those got
tests too.

**Final sweep: 47 attacks, 41 RED, 6 RED after new tests were added, 0 survivors.** Each RED names
the test that caught it — for example `NH4` → `TestAnAggregateThatExceedsACoverageAxisIsRefused`,
`NH7` → `TestSubRequiredStrengthMustBlock`, `CORROBORATION_LABEL_IS_EXACT` →
`TestCorroborationLabelsAreExactInBothDirections`, "closed strength vocabulary" →
`TestAnUnrankedStrengthIsAnErrorNotAPass`, "rust mutation disposition is obligation-specific" →
`TestRetainedReportsAreExactlyWhatTheEvidenceDerives`.

Independent of the sweep, these mutations were run against the artifacts and each was refused:

* aggregate rewritten to 24/24 in the retained JSON → byte comparison fails.
* one trailing line appended to each of the three retained artifacts → `verify` exits 1 on each.
* a catalog obligation statement edited → the proposal check `CATALOG_STILL_VENDORED_BYTES` fires,
  and `Reconcile` refuses outright.
* the Java projection re-pointed at a different catalog digest → `DeriveReport` refuses.
* the projection's `meets_required_strength` flipped true on a CONNECTED row → `DeriveReport`
  refuses, because the lattice disagrees.
* a correction proposal citation's `start_line` shifted by one → e2e lane RED, naming the real line.
* a span digest zeroed → e2e lane RED, printing the real digest.
* the unbindable `Charsetfunctions#stringUtf8` member promoted to bindable → e2e lane RED with the
  resolver's own ambiguity message.

**Corroboration labels are asserted in both directions.** A citation claiming
`PROOF_TARGETS_JAVA_AUTHORITY` whose digest is pinned nowhere is refused; a citation claiming
`PINNED_SOURCE_ONLY` whose digest **is** corroborated elsewhere is refused too. Both directions are
tested. A label that could only be too weak would be the same defect as one that could only be too
strong: it lets existence stand in for identity.

## 6. Hunting "existence standing in for identity"

The catalog's Java column is this programme's canonical example. Three checks in this branch exist
specifically so the reports do not reproduce that shape:

* Every citation carries a **file digest plus a byte span plus a structure fingerprint**, never a
  path alone, and the e2e lane recomputes all three.
* Every citation's corroboration is asserted **exactly**, both ways, so "this file is pinned
  somewhere" cannot be conflated with "this declaration is identified".
* Every declared basis pin is **compared**, not carried. Four had drifted and nobody knew.

And the reports themselves publish member lists beside every numerator, so "6/24" can be checked
against six names rather than trusted.

## 7. What I did NOT do, by name

* **I did not edit `assurance/formal/obligation-catalog.json`**, and no correction is adopted. The
  five obligations are still declared against the wrong symbols in the denominator this repository
  measures against. The report shows them as `CATALOG_DECLARES_A_JAVA_SYMBOL_THAT_CANNOT_CARRY_THE_OBLIGATION`.
* **I bound no new obligation.** `java_bindings_connected` stays 4/24,
  `java_bindings_at_required_strength` 0/24, `refinement` 0/24, `aggregate` 0/24. Nothing in this
  branch executes the Java oracle, compiles a mutant, or kills a canary.
* **I did not run the resolver.** `rust-analyzer` was not invoked; no Rust identity moved from
  `PLANNED_PENDING_RESOLVER`. The ceiling is reported, not lifted.
* **I did not repair the catalog's Rust column**, propose corrections for it, or attempt to map
  `websocket_core::` onto `ws_core::`. A name-normalising rule would have manufactured a mapping the
  documents do not have.
* **I did not correct `surface.errors.protocol-fault` or `surface.handshake.client-request`**, both
  of which carry catalog-defect reason codes. Out of the five I was asked to diagnose; named in the
  proposal so the omission is visible.
* **I did not resolve the four drifted basis pins.** Whether the catalog's declared basis or the
  files on disk are authoritative is an owner question; I only made the disagreement visible.
* **I did not reconcile the 19/24 Rust figure** in `docs/java-formal-binding-design.md` against the
  catalog's own `NOT_EXECUTED` rows. I recorded that the repository cannot compute it and left the
  design doc untouched.
* **I ran no owner gate**: no AWS, no benchmark, no Autobahn. No differential or handshake exam was
  re-run — this branch modifies no tracked file, so neither can have moved.
* **The e2e lane is not run by the default suite.** In the default lane the correction proposal's
  Java spans are provenance recorded in the artifact, not recomputed — the same bound
  `docs/java-formal-binding-design.md` section 5 states for the javabind receipt. I ran the executed
  lane in this session against the quarantined tree; a checkout without that tree does not.
* **Nothing here is independent.** Single Linux host, one session, owner-executed.

## 8. Gate readings, from this session's tool output

**`make -C rust gates` with `VJWP_PROTECTED_STORE` exported: exit 0.**
`ac1-gates verdict=PASS gates_passed=8/8`; `gate=canaries verdict=PASS detail="polarity proven:
good-scaffold passed scan/clippy/test (exits 0/0/0); bad-scaffold failed scan and clippy as required
(exits 1/101)"`; `gate=adapter-linkage verdict=PASS`; ledger integrity verified — 49 records, frozen
prefix through sequence 35, `unledgered_disagreements` recomputed = 0; owner-decision digests equal
the derivation and 6 governance record digests recomputed from the protected store and matched.

**`go build ./...` exit 0. `go vet ./...` exit 0.**

**`go test -count=1 -timeout 40m ./...`**: four packages failed, none of them mine.

| package | verdict |
| --- | --- |
| `internal/lab` | known baseline failure |
| `internal/portplan` | known baseline failure |
| `internal/deltaledger` | store unset only. Re-run as `VJWP_PROTECTED_STORE=… go test ./internal/deltaledger/` → **ok, 7.378s**. The refusal is the gate working as designed. |
| `internal/formalplan` | **pre-existing, and proved so.** I stashed every change (`git stash push -u`, `git status` clean) and re-ran on the pristine tree: still fails, `TestProofTargetsRealDocumentVerifies: unexpected finding JAVA_QUARANTINE_UNAVAILABLE at $.sources.quarantined_java_tree: JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned HTTP 403`. An offline/proxy refusal. Stash restored and verified. |

`internal/formalplan` was **not** on the list of known baseline failures I was given; it is a third
one, and this branch did not cause it.

**The existing Java lane is untouched and reads exactly as before:**

```
go test -count=1 ./internal/javabind/   ok
go run ./cmd/javabindctl verify -repo . exit 0
  java_bindings_connected=4/24
  java_bindings_partial=2/24
  java_bindings_disconnected=18/24
  java_mutation_sensitive=6/24
  java_bindings_at_required_strength=0/24
  refinement=0/24
  aggregate=0/24
```

**New packages:** `go test ./internal/formalcoverage/` ok; `go test ./cmd/formalcoverctl/` ok;
executed lane `FORMALCOVER_E2E_JAVA_SOURCE_ROOT=… go test -tags formalcovere2e -run E2E
./internal/formalcoverage/` ok, "recomputed 17 citation file digests from the pinned tree".

No owner gate was triggered: no AWS, no benchmark, no Autobahn.
