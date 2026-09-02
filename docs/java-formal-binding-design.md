# Java formal binding design

Status: OWNER_ATTESTED_NOT_INDEPENDENT; `independent_review_claimed: false`; production: false;
publication: false; signing: false.

This document defines what a *Java formal binding* means in this laboratory, what evidence
discharges one, exactly what the resulting claim is, and — at least as importantly — what it is
not. Read the "What this is not" section before quoting any number from
`evidence/java/formal-bindings/coverage-projection.json`.

## 1. The problem this design exists to solve

The programme's independent-acceptance gate (master US-008, third acceptance criterion) requires
"independently recomputed Java-versus-Rust formal coverage over a language-neutral
semantic-obligation denominator, with exact shipped production-symbol mappings, honest per-side
evidence strength, assumptions and bounds, paired comparability, production linkage, refinement
coverage, counterexample sensitivity, and zero blocking gaps".

The denominator is the immutable 24-obligation catalog. On the Rust side the other plane (Codex)
has driven production-symbol proof coverage and obligation-specific mutation sensitivity to 19/24.
On the Java side the standing count is **0/24**, and the frozen US-023 projection records why: every
one of the catalog's 24 `java_bindings` entries carries `connection_state: "DISCONNECTED"` and the
blocker

```
blocker-java-source  JAVA_SOURCE_OBJECT_UNAVAILABLE  SELF_CONTAINED_JAVA_BYTES_ABSENT
```

Inspecting those entries shows the shape of the gap precisely:

* `source_path` is a synthesised path (`upstream-java/org/java_websocket/drafts/Draft_6455/translateSingleFrame.java`)
  that exists in no tree, in this repository or upstream;
* `source_sha256` is `sha256:f44e7647…` — the digest of the **entire** quarantined source archive —
  and is byte-for-byte the same value on all 24 entries, so it distinguishes nothing;
* `identity.commit`, `identity.tree` and `identity.blob` are all `null`.

So the Java side of the denominator names symbols but binds no content. A number computed from
those entries would be a number about a filename, not about a program. That is the specific trap
this design is built to avoid.

## 2. What a "Java formal binding" can honestly mean here

The Java side is a JVM library — `org.java-websocket:Java-WebSocket:1.6.0`, pinned by digest
`sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f`. There is no Kani for
Java in this laboratory, no JML/OpenJML/KeY lane, and no budget to build one. **A "formal binding"
here therefore cannot mean, and does not mean, a proof of the Java library.**

What it *can* mean is a binding in the sense the acceptance criterion actually uses the word: a
connection between one catalog obligation and one identified piece of shipped Java, strong enough
that the connection can be falsified mechanically. Four things together make such a connection
falsifiable:

1. **Catalog anchor.** The obligation is one of the 24 in the immutable catalog, and the catalog is
   identified by content, not by path.
2. **Content-identified production construct.** The Java production symbol the catalog declares for
   that obligation resolves, inside the digest-pinned Java-WebSocket 1.6.0 source tree, to exactly
   one declaration, recorded as a byte span with its own digest.
3. **Executed observation.** One or more scenarios, executed out of process against the pinned JAR
   through the checked-in `java-oracle` adapter, whose byte-exact response lines are retained, and
   over which a named predicate for the obligation evaluates true.
4. **Clause-specific Java mutation sensitivity, with a control.** For *each clause* of the
   obligation, one exact, minimal, digest-anchored edit *inside the bound construct's own byte span*
   in the pinned source, recompiled and repackaged into a runtime archive, flips at least one
   predicate of that same clause which held on the baseline — and a **control** archive, built by
   recompiling and repackaging the *unmutated* source through the identical toolchain, reproduces
   the baseline observation exactly.

Item 4 is what turns items 2 and 3 from two adjacent facts into a binding. Without it, an executed
observation at the process boundary is evidence about the library as a whole and cannot be
attributed to the named symbol; a black-box rejection does not tell you which line rejected. With
it, the claim is: *edit these exact bytes of this exact declaration and this exact observation
changes.* That is production linkage on the Java side, obtained the same way the Rust side obtains
counterexample sensitivity — by breaking the thing on purpose and watching the evidence notice.

Two details of item 4 were forced by building it, and both make it stricter:

* **Per clause, not per obligation.** An earlier draft gave each obligation one canary. That is not
  enough. A clause whose witnesses hold with no canary of its own could be discharged by behaviour
  implemented somewhere else entirely — which is exactly what happens with the 125-octet control
  bound, whose witnesses the pinned Java satisfies but which is not implemented in the symbol the
  catalog names for it. Every clause now carries its own canary, or is explicitly marked as having
  none and is therefore not satisfied.
* **The control run.** A mutant is compiled by a different compiler than the one that built the
  pinned JAR, and is delivered through a repackaged archive. Either could move the observation on
  its own. The control isolates that: same compiler, same archive surgery, unmutated source. If the
  control does not reproduce the baseline byte for byte (modulo the runtime identity block, which
  necessarily differs), the canary earns no credit and the clause reports
  `CONTROL_DIVERGED_FROM_BASELINE`.

## 3. Definitions

### 3.1 Obligation clauses

Catalog statements are English sentences and several are conjunctions ("Control frames are final
**and** have payload length at most 125"). A binding that witnessed only one conjunct while being
counted as whole would be exactly the round-up this programme forbids. Each bound obligation is
therefore decomposed, once, in `assurance/formal/java-binding-spec.json`, into explicit **clauses**.
Every clause carries its own scenario/predicate witnesses. The decomposition is a reviewable
artifact, not an inference: it is written down, it is stable, and it is what the counting rule
consumes.

A clause is **satisfied** when all of: every one of its witness predicates holds against the
retained baseline response; it carries a canary inside the bound chain; that canary's control
reproduces the baseline; and the canary flips a witness *of that clause*.

* A binding is **CONNECTED** when every declared clause of the obligation is satisfied.
* A binding is **PARTIAL** when at least one but not every clause is satisfied.
* A binding is **DISCONNECTED** otherwise.

Only CONNECTED bindings are counted in the headline `java_bindings_connected` numerator. PARTIAL
bindings are reported separately and never folded into it. Clause-level totals
(`clauses_declared`, `clauses_satisfied`, `canaries_declared`, `canaries_killed`) are reported as
their own denominators, so an obligation with three clauses can never read as three obligations.

### 3.2 Symbol resolution, and what the catalog descriptors actually say

The catalog names Java symbols in JVM-descriptor form, e.g.

```
org.java_websocket.drafts.Draft_6455.translateSingleFrame(Ljava/nio/ByteBuffer;)Ljava/util/List;
```

Several of those descriptors do not match the pinned source. `translateSingleFrame` returns
`Framedata`, not `List`. `processFrameContinuousAndNonFin` takes `(WebSocketImpl, Framedata, Opcode)`,
not `(Framedata, WebSocketImpl)`. These are defects in the catalog, and the catalog is immutable, so
they cannot be repaired here.

The resolution rule is therefore stated explicitly rather than fudged:

* The binding key is `declaringType#simpleName`. Resolution succeeds only when the declaring type
  declares **exactly one** member with that name in the pinned source — that is, only when the name
  identifies the construct unambiguously with no overload set to disambiguate.
* The parameter list and return type the pinned source actually declares are recorded, and compared
  against the catalog descriptor. The result is published per binding as
  `descriptor_agreement ∈ {EXACT, RETURN_DIVERGENT, PARAMETERS_DIVERGENT, BOTH_DIVERGENT}`.
* A divergence is **disclosed, never normalised away**, and never silently repaired. A binding whose
  name is ambiguous in its declaring type is refused outright.

This is more information than the catalog carries, not less. It never claims the descriptor matched.

### 3.3 Delegation chains

Some catalog symbols are entry points that delegate the property to a private helper in the same
compilation unit — `createBinaryFrame` delegates frame emission to `createByteBufferFromFramedata`
and `getSizeBytes`. A binding may therefore declare a **chain**: the catalog-declared symbol as
root, plus named delegates, each with its own span and digest, **all within the same pinned source
file**. The mutation canary must land inside one chain member, and the artifact records which.
Delegation is disclosed per binding (`chain` has more than one member); it is not hidden inside the
root's span.

### 3.4 Mutation encoding

A mutation is recorded as `{chain member, offset relative to that member's span, byte length,
sha256 of the removed bytes, replacement text}`. The tool refuses to apply a mutation whose removed
bytes do not hash to the recorded value, and refuses one whose offset falls outside the member span.

Encoding the *removed* bytes as a digest rather than as literal text is deliberate on two counts.
It keeps upstream Java source out of this repository, which the intake policy requires; and it
makes the mutation anchored to content rather than to a searchable string that a reformat could
move. The replacement text is authored here and is therefore in the clear.

### 3.5 Delivering a mutant without weakening a control

`java-oracle`'s `OracleMain` verifies at startup that the `Draft_6455` it loaded came from a regular
file whose bytes hash to the single accepted v1.6.0 digest, and exits before reading a request if
they do not. That is an anti-evasion control and it is exactly right for a baseline. It also means a
mutant cannot be delivered by shadowing the JAR with a classes directory, and it must not be relaxed
to make one possible.

So it is not relaxed. `OracleMain` is untouched, and every baseline still runs through it with its
pin intact. Mutant and control runs go through a separate project-owned entry point,
`assurance/formal/java-binding/MutantOracleMain.java`, which takes its expected runtime digest as a
command-line argument, verifies that the archive actually loaded has that digest, and then hands the
JSONL loop to `OracleMain.run` — so the protocol and engine code producing baseline, control and
mutant observations is the same code. The expected digest is computed on the Go side from the
archive it built; the Java side can only confirm an identity decided outside it, never admit an
unpinned one.

The archives themselves are the pinned JAR with the recompiled class files of one compilation unit
substituted in and every other entry copied byte for byte, so a variant differs from the pinned
runtime only in the compiled form of that single file.

### 3.6 Evidence strength label

Every Java-side binding produced by this machinery carries

```
observed_strength: "EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY"
```

The catalog's `required_strength` for all 24 obligations is `PRODUCTION_REFINEMENT`.
`EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY` is strictly weaker. The projection therefore
reports two different numerators over the same denominator of 24 and never conflates them:

* `java_bindings_connected` — obligations with a FULL binding as defined above;
* `java_bindings_at_required_strength` — obligations whose Java side reaches
  `PRODUCTION_REFINEMENT`. **This is 0/24 and this work does not move it.**

## 4. What evidence discharges a binding, concretely

| Component | Artifact | Verified by |
| --- | --- | --- |
| Catalog anchor | `assurance/formal/obligation-catalog.json` | sha256 and git blob id recomputed and compared against the pinned identity |
| Construct identity | pinned source tree `Java-WebSocket-da3cf2a…` | archive digest `sha256:f44e7647…`; per-file sha256; per-span sha256; structural fingerprint |
| Executed observation | `evidence/java/formal-bindings/receipt.json` | byte-exact request line and response line retained; both digests recomputed; the adapter re-verifies the JAR digest at startup and echoes the runtime identity in every response |
| Mutation sensitivity | same receipt | baseline, control and mutant responses for the same request; the control must reproduce the baseline and the flipped predicate is named |
| Coverage | `evidence/java/formal-bindings/coverage-projection.json` | recomputed from the receipt by `javabindctl verify`; the Go test recomputes it independently and compares |

Nothing in the projection is typed by hand. `javabindctl verify` derives every count from the
receipt, and `internal/javabind`'s tests derive them again and compare against the retained file. A
count that is edited without the underlying evidence changing fails the test.

## 5. Two lanes, and which checks live where

**Self-contained lane (default `go test ./...`).** Requires no JVM and no quarantined tree.
Recomputes: catalog identity; request digests from the retained canonical request bytes; response
digests from the retained response bytes; every predicate re-evaluated over the retained responses;
baseline-versus-mutant predicate divergence; the whole coverage projection and its counts.

**Executed lane (`-tags javabinde2e`, explicit absolute paths in the environment).** Requires the
promoted JDK, the pinned JAR, the SLF4J API JAR and the quarantined source tree. Rebuilds the
adapter, re-resolves every declaration span from the pinned source, re-applies every mutation,
re-runs every scenario baseline and mutant, and requires the response bytes to reproduce the
retained receipt exactly.

The split follows the repository's existing `oraclee2e` idiom. It is stated here because it bounds
the claim: in the default lane the source spans are *provenance recorded in the receipt*, not
recomputed. Only the executed lane closes that gap, and it is the lane that produced the receipt in
the first place.

## 6. What this round actually achieved

These numbers are derived by `javabindctl verify` from the retained evidence and re-derived by
`internal/javabind`'s tests. They are quoted here for orientation; the artifact is authoritative.

| Numerator | Value | Meaning |
| --- | --- | --- |
| `java_bindings_connected` | **4/24** | every declared clause satisfied, each with a controlled, killed canary inside the bound span |
| `java_bindings_partial` | **2/24** | some but not all clauses satisfied; never folded into the line above |
| `java_bindings_disconnected` | **18/24** | each with a typed reason code from the closed vocabulary |
| `java_mutation_sensitive` | **6/24** | obligations with at least one killed canary |
| `java_bindings_at_required_strength` | **0/24** | `PRODUCTION_REFINEMENT` is not reached and is not approached |
| `refinement` | **0/24** | unchanged by this work |
| `aggregate` | **0/24** | unchanged by this work |
| `clauses_satisfied` / `clauses_declared` | 9 / 11 | clause-level totals, reported separately so one obligation with three clauses never reads as three obligations |
| `canaries_killed` / `canaries_declared` | 10 / 10 | every canary that was declared flipped a predicate |

`java_mutation_sensitive` is deliberately *not* a coverage number and must not be read as one. It
counts obligations for which at least one canary flipped an observation — which is a statement about
attribution, not about whether the obligation is met. `surface.close.status-code` is in that six and
is still only PARTIAL: its invalid-UTF-8-reason canary does flip the observation, proving the
behaviour lives at the bound construct, while the clause's own witnesses fail because the behaviour
the pinned Java exhibits is not the behaviour the clause asserts. Only `java_bindings_connected`
speaks to coverage.

The four CONNECTED obligations are `obligation.checked-header-arithmetic`,
`obligation.preallocation-cap`, `obligation.length-canonical-7` and
`surface.fragmentation.continuation`. The two PARTIAL ones are `obligation.control-fin-and-length`
(the 125-octet bound is not implemented in the symbol the catalog names) and
`surface.close.status-code` (the pinned Java answers an invalid-UTF-8 close reason with a
`NullPointerException` rather than a typed 1007 fault).

The two partials are different kinds of fact. The control one is a finding about the *catalog*: the
symbol it names for that obligation implements only half of it. The close one is a finding about the
*pinned Java*, and it — along with the role-masking gap that keeps `obligation.role-masking` unbound
— was already recorded in the Behavior Delta Ledger, at sequences 32 and 18 respectively, before
this lane ran. `drafts/ledger-proposals/java-formal-binding-corroborations.json` therefore proposes
no new record and claims no novelty; it only attaches the newly executed, digest-bound evidence.

Two catalog descriptor divergences were found and are published per binding rather than normalised
away: `Draft_6455.translateSingleFrame` is `RETURN_DIVERGENT` (it returns `Framedata`, not `List`)
and `Draft_6455.processFrameContinuousAndNonFin` is `PARAMETERS_DIVERGENT` (it takes
`(WebSocketImpl, Framedata, Opcode)`, not `(Framedata, WebSocketImpl)`).

## 7. What this is NOT

This section is normative for anything that quotes this work.

* **This is not a proof of the Java library.** No theorem prover, model checker or abstract
  interpreter is applied to Java-WebSocket 1.6.0 anywhere in this design. "Formal binding" names the
  *link between an obligation and identified shipped code*; it does not upgrade the evidence on the
  other end of that link to a proof.
* **It is not "formally verified".** In this repository that phrase is reserved for named
  Kani-proved properties quoted with their bounds together with the refinement check. Nothing here
  is Kani-proved and nothing here is a refinement check.
* **It does not establish refinement.** Java-to-model, model-to-Rust, and Java-to-Rust refinement
  all remain at 0/24 and are untouched by this work.
* **It does not move the aggregate.** Aggregate obligation coverage remains 0/24 because aggregate
  coverage requires the Java side, the Rust side, refinement and mutation sensitivity to be
  satisfied *together* at the required strength, and the Java side is below required strength by
  construction.
* **It is not exhaustive on any obligation.** Every executed observation is a finite set of concrete
  scenarios with declared bounds. A satisfied predicate says the pinned Java behaved that way on
  those inputs. It says nothing about inputs not in the set.
* **It is not independent.** Everything here is owner-executed on a single Linux host in one
  session, with `assurance: OWNER_ATTESTED_NOT_INDEPENDENT` and
  `independent_review_claimed: false`.
* **A satisfied binding is not a claim that the Java behaviour is correct.** The `java-oracle`
  adapter reports Java behaviour and does not adjudicate it; RFC 6455 remains normative. Where the
  pinned Java demonstrably does not implement an obligation clause, this work records that as an
  unbound obligation with a typed reason and drafts a Behavior Delta Ledger proposal — it never
  reinterprets the obligation to fit the observed behaviour.
* **It does not change the Rust side.** No behaviour-bearing Rust is touched, so the Rust proof and
  mutation numerators, the differential evidence and the Rust gates are unaffected and remain
  comparable to their prior values.

## 8. Typed reasons an obligation stays unbound

Unbound obligations are not silently dropped. Each carries one of these codes in the projection:

| Code | Meaning |
| --- | --- |
| `CATALOG_SYMBOL_SCOPE_MISMATCH` | The catalog's declared Java symbol does not implement the obligation statement (for example, masking obligations declared against `Charsetfunctions.utf8Bytes`). |
| `CATALOG_SYMBOL_NOT_ON_EXECUTED_PATH` | The declared symbol exists but is not executed under the adapter (for example, `WebSocketAdapter.onWebsocketPing`, which the oracle listener overrides without calling `super`). |
| `INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE` | The declared symbol is an interface or abstract declaration with no body, so it can host no mutation canary. |
| `JAVA_CONSTRUCT_DOES_NOT_IMPLEMENT_CLAUSE` | The pinned Java demonstrably does not implement a clause of the obligation. A finding, not an omission. |
| `NOT_OBSERVABLE_THROUGH_ADAPTER` | The property is outside what the out-of-process adapter can observe (for example, concurrency ordering, or socket ownership). |
| `NOT_ATTEMPTED_THIS_ROUND` | In scope for the design, not built in this round. |

## 9. Attribution

The immutable 24-obligation catalog `assurance/formal/obligation-catalog.json` and its schema
`schemas/us023-formal-obligations-1.0.0.schema.json` are the Codex plane's work, read from
`origin/codex/race-catchup` and vendored here **byte-identically and unmodified** so that this
branch can bind against the same denominator. Their identity is asserted by digest and by git blob
id in `internal/javabind`'s tests, so any drift from the Codex originals fails a test rather than
passing quietly. The Codex plane is read-only from here; nothing in this work writes to it.

The `java-oracle` adapter, the pinned-artifact intake, and the `oraclee2e` two-lane idiom are
pre-existing project work reused unchanged.
