# US-023 formal coverage — BLOCKED

`us023-formal-coverage` · schema 1.0.0 · OWNER_ATTESTED_NOT_INDEPENDENT · independent_review_claimed: false

> **FREEZE BLOCKED.** 24 of 24 obligations block. US-023 AC3: evidence below the obligation's required strength blocks the freeze. The freeze is BLOCKED while any obligation is blocking, regardless of any aggregate.

Formal coverage of the immutable 24-obligation catalog, derived from the artifacts this repository actually holds. Every numerator is an unweighted count of named obligations and every axis publishes both the obligations it counted and the obligations that block it, so no aggregate can hide a blocking obligation. Evidence below an obligation's required strength is a BLOCK, not a discount.

## The denominator, and what reconciling it exposed

This repository carries **two** formal denominators. They are reconciled in `assurance/formal/denominator-reconciliation.json`; the mapping is derived, not asserted, and joins on the one key both documents carry — the pinned-Java construct `DeclaringType#memberName`, anchored on both sides to the same digest-pinned Java-WebSocket archive.

| | count |
| --- | ---: |
| Obligations in the immutable catalog | 24 |
| Targets in the US-006 proof-target plan | 10 |
| **Obligations that map onto no planned proof target** | **13** |
| **Proof targets named by no obligation** | **4** |
| Catalog Rust binding rows whose declared source path exists in no tree | 24 |

Obligations with no proof target — named, not summarised:

- `obligation.control-fin-and-length`
- `obligation.length-canonical-7`
- `obligation.mask-equation`
- `obligation.mask-involution`
- `surface.close.status-code`
- `surface.concurrency.command-order`
- `surface.control.ping-pong`
- `surface.errors.protocol-fault`
- `surface.framing.masking`
- `surface.handshake.client-request`
- `surface.messages.binary`
- `surface.messages.text-utf8`
- `surface.websocket-open`

Proof targets no obligation names:

- `target.formal.concurrency.no-data-race`
- `target.formal.connection.no-terminal-escape`
- `target.formal.control.payload-length-bound`
- `target.formal.messages.utf8-validation-total`

## Coverage

Every numerator below is an unweighted count of named obligations. Axes marked **not coverage** are reported because AC3 requires them and because they are non-zero; they are excluded from the aggregate by construction, and a reader who quotes one of them as coverage is quoting it against the artifact.

| axis | | coverage? | feeds aggregate | weighting |
| --- | ---: | --- | --- | --- |
| `java_coverage` | **0/24** | coverage | yes | NONE |
| `rust_coverage` | **0/24** | coverage | yes | NONE |
| `paired_comparable_coverage` | **0/24** | coverage | yes | NONE |
| `production_linkage_java` | **6/24** | **not coverage** | no | NONE |
| `production_linkage_rust` | **0/24** | **not coverage** | no | NONE |
| `refinement_coverage` | **0/24** | coverage | yes | NONE |
| `bound_parity` | **0/24** | **not coverage** | no | NONE |
| `counterexample_sensitivity_java` | **6/24** | **not coverage** | no | NONE |
| `counterexample_sensitivity_rust` | **0/24** | **not coverage** | no | NONE |
| `aggregate` | **0/24** | coverage | no | NONE |

**`java_coverage` — 0/24.** Obligations whose JAVA-side evidence reaches the obligation's own required_strength. Java evidence below that strength is not counted here and is not counted anywhere else either.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`rust_coverage` — 0/24.** Obligations whose RUST-side evidence reaches required_strength, read from the immutable catalog's own evidence rows.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`paired_comparable_coverage` — 0/24.** Obligations where BOTH sides reach required_strength AND their declared bounds are comparable. Pairing is an intersection, so it can never exceed either side.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`production_linkage_java` — 6/24.** Obligations whose Java evidence is bound to one identified declaration in the digest-pinned Java source, recorded as a byte span with its own digest.

> NOT COVERAGE. Production linkage says an obligation is attached to identified shipped code; it says nothing about the strength of the evidence at the other end of that attachment. This numerator is non-zero while java_coverage is zero, and the two must never be conflated.

Counted: `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-7`, `obligation.preallocation-cap`, `surface.close.status-code`, `surface.fragmentation.continuation`

Blocking on this axis: 18 — `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`production_linkage_rust` — 0/24.** Obligations whose Rust evidence is bound to a RESOLVER-VERIFIED shipped Rust symbol.

> NOT COVERAGE, and zero. No Rust identity in this repository is resolver-verified; see resolver_ceiling.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`refinement_coverage` — 0/24.** Obligations with a CONNECTED refinement link between the model subject and the shipped symbol.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`bound_parity` — 0/24.** Obligations where both sides declare bounds, so that the two sides' results are quoted under comparable assumptions.

> NOT COVERAGE. Bound parity is a precondition for comparing two sides, not a measure of either.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`counterexample_sensitivity_java` — 6/24.** Obligations for which at least one obligation-specific Java canary, placed inside the bound declaration's own span, flipped a predicate that held on the baseline.

> NOT COVERAGE. This counts attribution, not satisfaction: an obligation can be mutation-sensitive and still PARTIAL or DISCONNECTED.

Counted: `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-7`, `obligation.preallocation-cap`, `surface.close.status-code`, `surface.fragmentation.continuation`

Blocking on this axis: 18 — `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`counterexample_sensitivity_rust` — 0/24.** Obligations for which at least one OBLIGATION-SPECIFIC Rust mutant was killed. Mutants recorded as RETAINED_KILLED_DIFFERENT_SUBJECT are deliberately NOT counted: a mutant killed by some other obligation's evidence is not sensitivity for this one.

> NOT COVERAGE, and zero. All 24 catalog mutation dispositions read RETAINED_KILLED_DIFFERENT_SUBJECT.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

**`aggregate` — 0/24.** Obligations satisfying EVERY coverage axis at required strength simultaneously. Derived as the intersection of the coverage axes' member sets, never as a weighted sum of their numerators.

Blocking on this axis: 24 — `obligation.checked-header-arithmetic`, `obligation.control-fin-and-length`, `obligation.length-canonical-16`, `obligation.length-canonical-64-high-bit-zero`, `obligation.length-canonical-7`, `obligation.mask-equation`, `obligation.mask-involution`, `obligation.preallocation-cap`, `obligation.role-masking`, `surface.adapter.byte-stream`, `surface.close.status-code`, `surface.close.terminal-state`, `surface.concurrency.command-order`, `surface.control.ping-pong`, `surface.errors.protocol-fault`, `surface.fragmentation.continuation`, `surface.framing.frame-octets`, `surface.framing.masking`, `surface.handshake.client-request`, `surface.handshake.server-response`, `surface.limits.allocation`, `surface.messages.binary`, `surface.messages.text-utf8`, `surface.websocket-open`

## How the no-hiding rule is enforced

No weighted aggregate may hide a blocking obligation. Enforced three ways at once: no axis applies any weight (every axis declares weighting NONE and is derived as a count of rows); every axis publishes its counted and its blocking obligations by name, so a numerator can be checked against a list rather than trusted; and the aggregate is derived as the INTERSECTION of the coverage axes' member sets, so it is bounded above by the weakest axis and cannot be lifted by a strong one. The invariants below are recomputed on every derivation and a violated invariant refuses the report rather than annotating it.

| invariant | holds | statement |
| --- | --- | --- |
| `NH1` | holds | Every axis numerator equals the length of the obligation list it publishes. |
| `NH2` | holds | On every axis the counted and the blocking obligations partition the fixed denominator of 24 exactly once each. |
| `NH3` | holds | No axis counts an obligation it also reports as blocking. |
| `NH4` | holds | The aggregate is bounded above by every coverage axis and its members are a subset of every coverage axis's members, so it is an intersection and not a weighted sum. |
| `NH5` | holds | No axis applies any weight; every numerator is an unweighted count of obligations. |
| `NH6` | holds | Every blocking obligation appears in blocking_gaps with at least one named reason, and blocking_gaps names nothing else. |
| `NH7` | holds | Any obligation whose evidence is below its required strength on either side is blocking. |
| `NH8` | holds | The freeze verdict is BLOCKED exactly when at least one obligation blocks, and it names every blocking obligation. |
| `NH9` | holds | No axis that is not coverage feeds the aggregate, and any non-zero non-coverage numerator states in the artifact that it is not coverage. |
| `NH10` | holds | The report holds exactly 24 rows over 24 distinct obligations. |
| `NH11` | holds | While the proof-target plan records no resolver verification, the Rust production-linkage numerator, the resolver-verified planned-symbol count and the verified migration-binding count are all zero. |

A violated invariant does not annotate the report. `DeriveReport` returns an error and writes nothing, so a report that hides a blocking obligation cannot be produced by this tool at all.

## The resolver ceiling

NO formal obligation in this repository binds to a resolver-verified shipped Rust symbol: 0 of 24. The proof-target plan reads RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED with planned_resolver rust-analyzer and resolver_verified_at null; all 21 planned production symbols are PLANNED_PENDING_RESOLVER with resolved_symbol null, and all 98 migration bindings read rust_identity_verified=false. The strongest linkage evidence this repository holds, evidence/linkage/rust-identity-verification.json, resolves 45 of 47 rows by deterministic declaration scan (internal/linkage resolveSymbol) and labels its own strength "declaration-scan (reviewed-glancer class), not rust-analyzer semantic resolution". That overlay and the plan do not contradict each other and neither overstates itself; the ceiling is the CONJUNCTION of what they honestly say. Every claim that formal evidence here reaches shipped Rust code therefore rests on a declaration scan, not on semantic resolution, and no coverage percentage in this report may be read as implying otherwise.

| | |
| --- | --- |
| proof-target resolver state | `RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED` |
| planned resolver | `rust-analyzer` |
| resolver_verified_at | `null` |
| planned production symbols / resolver-verified | 21 / **0** |
| migration bindings / rust_identity_verified | 98 / **0** |
| strongest linkage overlay | `evidence/linkage/rust-identity-verification.json` |
| its method | deterministic declaration scan (internal/linkage resolveSymbol) |
| its own declared strength | declaration-scan (reviewed-glancer class), not rust-analyzer semantic resolution |
| its rows resolved | 45 / 47 |
| **obligations bound to a resolver-verified shipped Rust symbol** | **0 / 24** |

## Defects in the denominator itself

These are findings about the catalog, not about the programs it measures. An obligation declared against a symbol that cannot carry it is not an uncovered obligation; it is an unmeasurable one, and a coverage number over it would be a number about a name.

| obligation | side | defect | correction |
| --- | --- | --- | --- |
| `obligation.mask-equation` | JAVA | `CATALOG_SYMBOL_SCOPE_MISMATCH` | `correction.mask-equation` |
| `obligation.mask-involution` | JAVA | `CATALOG_SYMBOL_SCOPE_MISMATCH` | `correction.mask-involution` |
| `surface.control.ping-pong` | JAVA | `CATALOG_SYMBOL_NOT_ON_EXECUTED_PATH` | `correction.control-ping-pong` |
| `surface.messages.binary` | JAVA | `INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE` | `correction.messages-binary` |
| `surface.messages.text-utf8` | JAVA | `INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE` | `correction.messages-text-utf8` |
| `(10 obligations)` | RUST | `SOURCE_PATH_EXISTS_IN_NO_TREE+NAMESPACE_MATCHES_NO_SHIPPED_CRATE` | — |
| `(9 obligations)` | RUST | `SOURCE_PATH_EXISTS_IN_NO_TREE+NAMESPACE_MATCHES_NO_SHIPPED_CRATE` | — |
| `(3 obligations)` | RUST | `SOURCE_PATH_EXISTS_IN_NO_TREE+NAMESPACE_MATCHES_NO_SHIPPED_CRATE` | — |
| `(2 obligations)` | RUST | `SOURCE_PATH_EXISTS_IN_NO_TREE+NAMESPACE_MATCHES_NO_SHIPPED_CRATE` | — |

## Every obligation

| obligation | java | rust | refinement | bound parity | targets | blocking |
| --- | --- | --- | --- | --- | --- | --- |
| `obligation.checked-header-arithmetic` | EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY | NONE | DISCONNECTED | ONE_SIDE_DECLARES_A_BOUND_AND_THE_OTHER_DOES_NOT | 2 | **9** |
| `obligation.control-fin-and-length` | EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY | NONE | DISCONNECTED | ONE_SIDE_DECLARES_A_BOUND_AND_THE_OTHER_DOES_NOT | **none** | **10** |
| `obligation.length-canonical-16` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 2 | **11** |
| `obligation.length-canonical-64-high-bit-zero` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 2 | **11** |
| `obligation.length-canonical-7` | EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY | NONE | DISCONNECTED | ONE_SIDE_DECLARES_A_BOUND_AND_THE_OTHER_DOES_NOT | **none** | **10** |
| `obligation.mask-equation` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **13** |
| `obligation.mask-involution` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **13** |
| `obligation.preallocation-cap` | EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY | NONE | DISCONNECTED | ONE_SIDE_DECLARES_A_BOUND_AND_THE_OTHER_DOES_NOT | 2 | **9** |
| `obligation.role-masking` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 2 | **11** |
| `surface.adapter.byte-stream` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 1 | **11** |
| `surface.close.status-code` | EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY | NONE | DISCONNECTED | ONE_SIDE_DECLARES_A_BOUND_AND_THE_OTHER_DOES_NOT | **none** | **10** |
| `surface.close.terminal-state` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 1 | **11** |
| `surface.concurrency.command-order` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **12** |
| `surface.control.ping-pong` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **13** |
| `surface.errors.protocol-fault` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **12** |
| `surface.fragmentation.continuation` | EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY | NONE | DISCONNECTED | ONE_SIDE_DECLARES_A_BOUND_AND_THE_OTHER_DOES_NOT | 1 | **9** |
| `surface.framing.frame-octets` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 2 | **11** |
| `surface.framing.masking` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **12** |
| `surface.handshake.client-request` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **12** |
| `surface.handshake.server-response` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 1 | **11** |
| `surface.limits.allocation` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | 2 | **11** |
| `surface.messages.binary` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **13** |
| `surface.messages.text-utf8` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **13** |
| `surface.websocket-open` | NONE | NONE | DISCONNECTED | NEITHER_SIDE_DECLARES_A_BOUND | **none** | **12** |

## Every blocking gap

All 24 of them, each with its reasons. No aggregate in this report can shrink this list.

### `obligation.checked-header-arithmetic`

Header and payload arithmetic is checked before allocation.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.control-fin-and-length`

Control frames are final and have payload length at most 125.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.length-canonical-16`

The 16-bit length form is canonical.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.length-canonical-64-high-bit-zero`

The 64-bit length form is canonical and has a clear high bit.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.length-canonical-7`

Payload lengths through 125 use the seven-bit form.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.mask-equation`

Masking applies RFC 6455 XOR at the correct offset.

- `CATALOG_DECLARES_A_JAVA_SYMBOL_THAT_CANNOT_CARRY_THE_OBLIGATION`
- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.mask-involution`

Applying the same mask twice restores the input.

- `CATALOG_DECLARES_A_JAVA_SYMBOL_THAT_CANNOT_CARRY_THE_OBLIGATION`
- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.preallocation-cap`

Configured caps are enforced before payload allocation.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `obligation.role-masking`

Inbound masking is enforced by endpoint role.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.adapter.byte-stream`

The adapter transports bytes without protocol duplication.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.close.status-code`

Close status codes and reasons are validated.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.close.terminal-state`

Terminal close state is absorbing.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.concurrency.command-order`

Concurrent commands have one serialized owner order.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.control.ping-pong`

Ping and pong control behavior preserves payloads and bounds.

- `CATALOG_DECLARES_A_JAVA_SYMBOL_THAT_CANNOT_CARRY_THE_OBLIGATION`
- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.errors.protocol-fault`

Protocol faults remain typed and fail closed.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.fragmentation.continuation`

Continuation fragments are admitted and assembled in order.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.framing.frame-octets`

Frame octets are parsed and emitted canonically.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.framing.masking`

Masking uses the RFC 6455 transform and role rules.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.handshake.client-request`

Client opening requests follow RFC 6455.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.handshake.server-response`

Server opening responses follow RFC 6455.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.limits.allocation`

Allocation limits are enforced before retaining payload bytes.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.messages.binary`

Binary message payloads are delivered exactly.

- `CATALOG_DECLARES_A_JAVA_SYMBOL_THAT_CANNOT_CARRY_THE_OBLIGATION`
- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.messages.text-utf8`

Text messages accept exactly valid UTF-8.

- `CATALOG_DECLARES_A_JAVA_SYMBOL_THAT_CANNOT_CARRY_THE_OBLIGATION`
- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

### `surface.websocket-open`

The declared WebSocket opening seam enters the shipped connection core.

- `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE`
- `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE`
- `DECLARED_BOUNDS_ARE_NOT_COMPARABLE`
- `JAVA_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `JAVA_SIDE_NOT_BOUND_TO_AN_IDENTIFIED_DECLARATION`
- `NO_KILLED_OBLIGATION_SPECIFIC_JAVA_CANARY`
- `NO_OBLIGATION_SPECIFIC_RUST_COUNTEREXAMPLE_OR_MUTANT`
- `OBLIGATION_MAPS_ONTO_NO_PLANNED_PROOF_TARGET`
- `REFINEMENT_LINK_DISCONNECTED`
- `RUST_EVIDENCE_BELOW_REQUIRED_STRENGTH`
- `RUST_EVIDENCE_NOT_EXECUTED`
- `RUST_SIDE_NOT_BOUND_TO_A_RESOLVER_VERIFIED_SHIPPED_SYMBOL`

## What this report does not claim

- No number in this report is a proof. Nothing here proves anything about Java-WebSocket 1.6.0 or about the shipped Rust; the report measures what evidence exists and at what strength.
- Non-zero numerators on the production-linkage and counterexample-sensitivity axes are NOT coverage and are labelled so in the artifact. Coverage is java_coverage, rust_coverage, paired_comparable_coverage, refinement_coverage and aggregate, and all five are zero.
- The six Java production-linkage rows are span digests QUOTED from evidence/java/formal-bindings/receipt.json. In the default lane those spans are provenance recorded in that receipt, not recomputed from the pinned Java tree; only the javabinde2e lane recomputes them. This report inherits that bound and does not close it.
- The denominator itself is defective on both sides — five obligations declare Java symbols that cannot carry them, and all 24 declare Rust source paths that exist in no tree — so even a perfect score over it would not mean what it appears to mean. The defects are listed rather than corrected here.
- This report is owner-executed on a single host. assurance is OWNER_ATTESTED_NOT_INDEPENDENT and independent_review_claimed is false.

## Inputs

| artifact | sha256 |
| --- | --- |
| `assurance/formal/obligation-catalog.json` | `sha256:21112518f48443b4e20ecae537bed72b8c9e19167ad00bc6f325bff9374cdf59` |
| `assurance/formal/proof-targets.json` | `sha256:bad1e0697d0f4428a4cc6572549e4528ca4f0328c15163beddd4deb31c59a205` |
| `evidence/java/formal-bindings/coverage-projection.json` | `sha256:02a9b1302cca2b340253ff1ed1fa1fe024a45da68c01b95a85659105121460ef` |
| `assurance/formal/java-binding-spec.json` | `sha256:468142c6d01a8c358e636f4f52aefd564c5d9854c824ece3008be67d4da7c15b` |
| `evidence/linkage/rust-identity-verification.json` | `sha256:5370eb0856a1f0f3d5c6c10999710d6189c06c0dfedd81c64bb0c1cf42563833` |
| `assurance/formal/catalog-correction-proposal.json` | `sha256:fceb6bf4fae057a4e287a367ed255a7a616256de785a8ac2c56e2d7d0a709c38` |
| `assurance/formal/denominator-reconciliation.json` | `sha256:fa54066acdccd7f733f15100a0b05df7ea4a932e30999e3e15615b723ca0f5db` |

Generated by `go run ./cmd/formalcoverctl report -repo .` from the artifacts above. `go run ./cmd/formalcoverctl verify -repo .` recomputes both reports and fails if the retained bytes are not what the evidence derives; `go run ./cmd/formalcoverctl freeze-gate -repo .` exits non-zero while any obligation blocks.
