# Landing record — claude/java-formal-bindings → mainline (goal-loop, parallel-agent track D)

Recorded 2026-09-02 by the goal loop from tool output. The branch carries its
own review round (20 deletion attacks, two over-claims caught and corrected
mid-round). This record is the landing check the loop ran on top of it:
OWNER_ATTESTED_NOT_INDEPENDENT.

## What landed

One commit, `aa5c348`, 26 files, **all additions — zero modifications, zero
deletions**. No tracked file was changed, so no behaviour-bearing byte moved and
the differential and handshake exam surfaces cannot have shifted by it.

## The Codex borrow, verified rather than accepted

The obligation catalog was not on mainline; it lives on the read-only Codex
plane. The branch vendored two files from `origin/codex/race-catchup`. Both were
checked against that plane directly:

| File | Codex blob | Branch blob | |
| --- | --- | --- | --- |
| `assurance/formal/obligation-catalog.json` | `be929320…97d2b` | `be929320…97d2b` | **identical** |
| `schemas/us023-formal-obligations-1.0.0.schema.json` | `8ebc8187…bb25c` | `8ebc8187…bb25c` | **identical** |

Catalog sha256 `21112518f48443b4e20ecae537bed72b8c9e19167ad00bc6f325bff9374cdf59`,
exactly as the branch reports. The Codex plane was read, never written. The
branch asserts both the sha256 and the git blob id in a test, so drift fails
rather than passing quietly — that is the receipt the borrow requires.

## Why Java read 0/24, confirmed at source

The branch's diagnosis is that the catalog's Java side named symbols and bound
no content. Verified directly against the vendored bytes:

- All **24** `java_bindings` entries read `connection_state: DISCONNECTED`.
- Their `source_path` values are synthesised paths that treat a *method* as a
  file — `upstream-java/org/java_websocket/drafts/Draft_6455/translateSingleFrame.java`,
  `upstream-java/org/java_websocket/framing/ControlFrame/isValid.java`. No such
  path exists in any tree; the real source is one `Draft_6455.java` holding many
  methods. 15 distinct such paths across 24 bindings.
- **All 24 share ONE `source_sha256`**, `sha256:f44e7647…13cb4` — the
  whole-archive digest, the same value agent B independently read as the pinned
  archive's digest.

Twenty-four distinct obligations, one archive-level digest, paths that resolve
to nothing. This is the defect class this program keeps rediscovering, stated in
its purest form yet: **existence standing in for identity.** The catalog's Java
column looked populated and bound nothing.

## What the branch put in its place, and at what strength

4/24 CONNECTED, 2/24 PARTIAL, 18/24 DISCONNECTED, 6/24 mutation-sensitive.
Each connected binding resolves its declared symbol to exactly one declaration
recorded as a digest-bound byte span in the pinned Java-WebSocket 1.6.0 source,
carries predicates over byte-exact `java-oracle` responses from the pinned JAR,
and — per clause — one digest-anchored edit inside that declaration's own span
that flips a predicate of that clause, with a recompiled-but-unmutated control
reproducing the baseline. 30 retained runs (10 baseline, 10 control, 10 mutant);
11 clauses declared, 9 satisfied; 10 canaries declared, 10 killed.

**The tool refuses to let 4/24 be read as progress toward the required bar.**
`go run ./cmd/javabindctl verify -repo .` (exit 0) prints the ceiling on the
same screen as the numerator:

```
java_bindings_connected=4/24
java_bindings_at_required_strength=0/24
refinement=0/24
aggregate=0/24
observed_strength=EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY required_strength=PRODUCTION_REFINEMENT
assurance=OWNER_ATTESTED_NOT_INDEPENDENT independent_review_claimed=false
```

`EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY` is strictly weaker than the
`PRODUCTION_REFINEMENT` all 24 obligations require. **Master US-008's formal
denominator does not move: Java stays 0/24 at required strength, refinement
0/24, aggregate 0/24.** What changed is that four obligations now have
falsifiable Java-side evidence where before they had a synthesised path and an
archive digest.

## The loop's own probe of the content binding

The branch claims that appending one whitespace byte to the catalog is refused —
the "existence versus content identity" trap it says it hunted explicitly. Rather
than take that on report, the loop ran it: appended a single space to
`assurance/formal/obligation-catalog.json` and re-ran the verifier.

```
javabindctl: javabind: the catalog on disk is not the catalog the spec pins
exit status 1
```

The binding is to content, not to existence, and the refusal names the problem.
The file was restored and re-checked byte-identical to the Codex blob
(`21112518…cdf59`).

## Honest ceiling, transcribed from the branch and not softened

- Not a proof of Java-WebSocket 1.6.0. No prover or model checker touches it.
- Not "formally verified". Establishes no refinement. Does not move the aggregate.
- Non-exhaustive: finite scenario sets.
- Owner-executed, single Linux host, `OWNER_ATTESTED_NOT_INDEPENDENT`.
- **In the default lane the Java source spans are provenance recorded in the
  receipt, not recomputed.** Only the `javabinde2e` lane recomputes them from the
  quarantined tree. A default-lane verify therefore trusts the receipt's spans.

## What remains, as the branch names it

`surface.handshake.server-response` is the most reachable next
(`postProcessHandshakeResponseAsServer` is genuinely executed by the handshake
oracle; it needs the second request shape). `surface.close.terminal-state`,
`surface.adapter.byte-stream`, `surface.framing.frame-octets` and
`surface.limits.allocation` need distinct clause sets and canaries that do not
double-credit an existing witness. **Five are blocked by catalog defects the
branch cannot repair** — the mask obligations are declared against
`Charsetfunctions.utf8Bytes`, `ping-pong` against a method the oracle listener
overrides, and `messages.*` against an ambiguous interface overload. Three are
not observable through this adapter at any strength. The two PARTIALs need a
decision from the ledger-owning track, not more engineering.

That five of the 24 are blocked by defects *in the catalog itself* is worth
carrying to the US-023 audit: the denominator this program measures against has
obligations declared against the wrong Java symbols.

## Gates, read at the merged head

- `make -C rust gates` with the store exported: **exit 0**;
  `ac1-gates verdict=PASS gates_passed=8/8`; ledger integrity verified (48
  records, frozen prefix through 35, unledgered_disagreements 0); 75
  `test result: ok`, **0 failed**.
- `go build ./...` exit 0. `go test -count=1 ./internal/javabind/` exit 0.
- `go run ./cmd/javabindctl verify -repo .` exit 0, output above.
- No tracked file was modified by this branch, so the differential and exam
  cannot have moved; they were re-run at `d433c21` for track B and read port
  74/74 and 49/49, live Java 74/74 and 49/49, same 16 divergences.
