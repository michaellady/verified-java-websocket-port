# F019 — a master criterion hidden behind a child criterion of the same name, and a blocking rule with no mechanism

phase: master-story and PRD-metadata sweep   step: n/a   date: 2026-09-04T00:00Z

## The criterion

`docs/prd-pack/03-master-stories-intake-lsp-protocol-labzero.md:13`, master
US-020 AC5:

> A Behavior Delta Ledger classifies every Java/Rust/spec disagreement as
> **preserve, intentionally-correct with authoritative before-and-after
> evidence, or unresolved**; **unresolved deltas block completion** and a
> refutation or later pass never erases the original finding or adjudication
> history.

Three operative parts: a **vocabulary**, a **blocking rule**, and a
**no-erasure rule**.

## Why four passes over this repository's ledger never saw it

`internal/ac5class` exists. It is named for "US-020 AC5". Its own header
(`internal/ac5class/register.go:4`) reads:

> US-020 AC5 (docs/prd-pack/07c-child-prd-us020-us027.md) names seven defect
> classes by hand

That is the **child's** US-020 AC5 — a list of seeded defect classes. The
**master's** US-020 AC5, quoted above, is a different clause in a different
document about a different subject. `register.go:53` pins
`const PRDPath = "docs/prd-pack/07c-child-prd-us020-us027.md"`, so the package
that carries the criterion's name can only ever read the child's.

The master clause's distinguishing phrase settles it:

```
grep -rn "intentionally-correct" .
  → 1 hit: docs/prd-pack/03-master-stories-intake-lsp-protocol-labzero.md:13
```

**Exactly one occurrence in the repository, and it is the PRD line itself.**
`docs/prd-pack/README.md` warns that master and child stories share ids; what it
does not warn about is that they share *criterion numbers* too, and that a
package named for one makes the other look covered. Searching this tree for
"US-020 AC5" returns a Go package, a self-review record and a gate — all of them
about the child.

## Part one — the vocabulary, and a conflict inside this repository

Recomputed from `evidence/java/behavior-delta-ledger.json`: **59** records,
**52** `unresolved`, 3 `adopt-java`, 3 `fix-in-port`, 1
`intentional-correction`.

AC5's three terms map onto the port's vocabulary, and the port says so itself.
`schemas/behavior-delta-ledger-1.2.0.schema.json:207` describes its three added
terms as *"the inherited foundation schema's adoption/correction axis
(`assurance/schema/behavior-delta-ledger.schema.json` PRESERVE /
INTENTIONALLY_CORRECT / UNRESOLVED) in this ledger's spelling"*, and that
foundation schema's `classification` enum is literally
`["PRESERVE","INTENTIONALLY_CORRECT","UNRESOLVED"]` — master US-020 AC5's three
classes, verbatim. So the mapping exists and is documented.

**The conflict is that the shipped records do not carry the mapped term, and the
tree holds two incompatible accounts of what the term they do carry means.**

`internal/lab/ledger.go:78-80`, the enum's own definition:

```go
// DispositionUnresolved: no adjudication has been made. The mismatch
// stands and the decision is owed. Unchanged from the 1.0.0 vocabulary.
DispositionUnresolved = "unresolved"
```

`internal/deltaledger/definitions.go:23-29`, the package that builds the records:

```go
// The ledger's frozen 1.0.0 vocabulary ... disposition admits only
// "unresolved" or "rfc-governs". Records therefore carry disposition
// "unresolved" — the divergence is deliberately retained under the owner's
// JAVA_FAITHFUL_PLUS_SAFE decision, not resolved toward the RFC ...
```

One says the decision is **owed**. The other says the decision is **made** and
the token is a spelling forced by a frozen schema. Both are in production code,
about the same field, in the same repository.

**Measured, so the size of the disagreement is not a guess.** Counting records
whose hashed rationale carries the retention marker *"disposition is 'unresolved'
because the frozen 1.0.0 vocabulary has no java-faithful term"*:

- 52 `unresolved` total
- **45** carry the marker — by `definitions.go`'s account these are AC5's
  **`preserve`**, and the ledger's face value calls them `unresolved`
- **7** do not: sequences 33, 34, 35, 49, 53, 55, 58
- of those 7, three are superseded (34→57, 55→58, 58→59), leaving **4 live**:
  sequences **33, 35, 49, 53**

So under AC5's vocabulary the ledger's face value misstates the classification of
**45** disagreements, by the port's own in-code account of them. Under the
generous reading that account governs and only **4** are truly `unresolved`.
Either way the number the artifact publishes — 52 — is the wrong one on both
readings.

## Part two — the blocking rule has no mechanism anywhere in the tree

**Nothing blocks on `unresolved`.**

```
grep -rn "DispositionUnresolved" --include="*.go" .
```

returns six non-test lines in three files: `internal/lab/ledger.go:78,80,116`
(comment, declaration, vocabulary list), `internal/deltaledger/build.go:264`
(the empty-field default), and `internal/deltaledger/adjudication.go:157,162`.
The only one that reads the value in a conditional is `adjudication.go:157`, and
it uses it as a **permission**, not a refusal:

```go
// 3. AN ADJUDICATED RECORD IS CLASSED.
if !classed && delta.Disposition != lab.DispositionUnresolved {
```

— an unclassed record *must* be `unresolved`. The opposite direction.

The ledger's readiness verifier is `internal/lab/evidence.go:830-864`. It checks
supersession-link equality, `unledgered_disagreements == 0`,
`records_without_mismatch_class` against the record chain, and that `status` is
inside `{READY, BLOCKED_PENDING_BASELINE}`. **No arm of it counts unresolved
dispositions or refuses on them.**

The committed `status` *is* `BLOCKED_PENDING_BASELINE`, and it would be easy to
read that as AC5's blocking rule working. It is not.
`assurance/concurrency/plan.json`'s `append_blocker` says why, in its own words:

> the Autobahn baseline is BLOCKED (0/247 both modes,
> NO_FURTHER_RERUNS_AUTHORIZED), so ledger status stays
> BLOCKED_PENDING_BASELINE

A different condition entirely. Remove the Autobahn block and the ledger goes
`READY` with 52 records reading `unresolved` and nothing objecting.

## The correction I had to make to my own finding, recorded rather than deleted

I first wrote this finding as a breach: *"the child declared
`STORY_EXECUTION_COMPLETE` with 52 unresolved deltas standing, and AC5 says
unresolved deltas block completion."* **That is wrong, and the document I was
already quoting says so.**

`docs/prd-pack/01-structure-and-index.md:121`:

> A sibling **verified-java-websocket-port-claude** (branch
> `claude/feature/verified-java-websocket-port`, updated 2026-08-25) has the same
> 27 stories with **9 marked done**; it is the Claude-runtime variant and is not
> the canonical child.

**This repository is that sibling.** Its mainline branch is
`claude/feature/verified-java-websocket-port`; every owner decision in
`evidence/governance/decisions/` carries
`"plane": "verified-java-websocket-port-claude (Claude authority plane)"`; and
`.claude/GOAL-LOOP.md:780` records `Stories with passes: true | 9 (per handoff)`.
The 27/27 `STORY_EXECUTION_COMPLETE` belongs to the **canonical** child, whose
ledger is not in this repository and which I have not seen.

**So AC5's blocking rule is not breached here.** This plane has declared no
completion for it to block. What is true here is narrower and is what this
finding claims: the classification is misstated on its face, and the rule that
would stop a completion declaration has no mechanism, so if this plane reaches
that point nothing will fire.

I am recording the wrong version rather than quietly replacing it, because the
error is the one this repository keeps paying for — reading a criterion against
the nearest available subject instead of the one it governs — and because the
line that refuted it was already inside a file I had quoted twice.

## The four live unresolved records, and the decision grep on each

Run before calling any of them a finding, with `VJWP_PROTECTED_STORE` exported:

| seq | subject | decision cited in its own hashed rationale |
|---|---|---|
| 33 | `close-echo-wire-composition` | `us010-016-ac-amendment-owner-decision-2026-08-27.json` |
| 35 | `rejected-local-close-readystate` | `us012-us016-owner-decisions-2026-08-28-formal.json` |
| 49 | `protocol-violation-close-reaction` | `us017-c6-layer-split-…`, `us017-post-failure-…` |
| 53 | `invalid-utf8-reason-transport-stall` | **none** |

Three of the four cite a standing decision and retain `unresolved` anyway —
which is defensible, and sequence 59 drew the distinction explicitly when it
ruled on sequence 58: a decision about the **behaviour** need not settle the
**disposition**. **Sequence 53 is the only live delta in this ledger with no
owner decision anywhere bearing on it**, and it carries
`mismatch_class: java-quirk`.

And `grep -rli "master" evidence/governance/decisions/` returns one file,
`company-move-record.json`, about a company folder move. **No standing owner
decision names master US-020, the master PRD, or its metadata.** The two
instruments that clear the equivalent child clauses do not reach here: the
2026-08-27 amendment is scoped to *"every AC clause of US-010..US-016"* and
master US-020 is not in that range under either namespace, and
`JAVA_FAITHFUL_PLUS_SAFE` is a stance about wire behaviour, not about a ledger
vocabulary.

## What is satisfied, said as plainly as what is not

AC5's **third** part — *"a refutation or later pass never erases the original
finding or adjudication history"* — is satisfied, and well. The frozen prefix
through sequence 35 is byte-identical; corrections happen by supersession, six
of them (14→45, 15→46, 16→47, 34→57, 55→58, 58→59); every superseded record
stays in the chain with its digest intact; and
`ledger-frozen-prefix-owner-decision-2026-08-28.json` ruled *"SUPERSEDE, DO NOT
REWRITE"* for exactly this reason. This is the part of AC5 the repository
implements best, and it implements it without ever having read the clause.

## Bin

F016's class — *the gate a criterion names cannot detect what the criterion
promises* — with a naming twist that made it worse. In F016 the gate existed and
was too narrow. Here the criterion's blocking rule has **no** gate, and the
package that carries the criterion's name implements a **different criterion of
the same number in a different document**. A reader checking "is US-020 AC5
covered?" finds `internal/ac5class`, a self-review record and a passing gate, and
stops.

The portable rule: when two documents in a corpus share a story-numbering scheme,
a criterion citation is ambiguous until it names the document. Every `US-020 AC5`
citation in this tree names its file. That is exactly what let the collision
survive — each citation is individually correct, and none of them is about the
master.

## Owner decision required

1. **Does master US-020 AC5's vocabulary bind this ledger's face value, or its
   documented intent?** On the face value, 45 records are misclassified; on the
   intent, 4 are genuinely unresolved and the published 52 overstates it. Either
   way the shipped number is not the criterion's number.
2. **Should AC5's blocking rule have a mechanism?** Today it has none, and this
   plane is 9/27 rather than complete, so the absence has cost nothing yet.
3. **Sequence 53** is the one live delta with no decision bearing on it.

## Status

Filed, with one self-correction recorded above rather than deleted. No ledger
record edited, no disposition changed, no denominator re-baselined. Corpus
derivation, the robustness table this came out of, and the ceiling:
`drafts/self-review/master-story-sweep.md`.
