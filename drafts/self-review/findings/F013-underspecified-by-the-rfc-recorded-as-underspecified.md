# F013 — "underspecified by the RFC" recorded as "underspecified"

## What I was looking for, and what refuted it

I went looking for a vacuous field. Ledger record `normative_authority` takes
the value `rfc6455` in **all 56 records** — not one has ever carried anything
else — and this repository has filed several defects of exactly that shape: a
field that looks like it records a choice and records nothing
(`deferred_frame_dispatch` summed into totals and never read;
`behaviour.envelope_error` comparing nothing because the transcript cannot be
loaded).

The code refutes it. `internal/lab/ledger.go:137-138`:

```go
if d.NormativeAuthority != "rfc6455" {
    return finding("INVALID_ORACLE_AUTHORITY", "$.normative_authority",
        "RFC 6455 must remain normative over Java and Autobahn observations")
}
```

The constant is **enforced**, deliberately, and for a good reason: it stops
anyone from declaring Java or Autobahn normative over the RFC. That is an
anti-drift guard doing real work, and `internal/lab/evidence.go:811` checks the
same invariant at the document level. My hypothesis was wrong and I am recording
that it was wrong, because the shape of the real finding is only visible once
you accept that the guard is correct.

## The real finding

Read the guard's own words: "RFC 6455 must remain normative over **Java and
Autobahn observations**."

Its purpose is to stop *observations* outranking the specification. The ledger's
authority model therefore has exactly one normative pole — RFC 6455 — and three
observation sources: Java, Autobahn, and the port. **This project's own
acceptance criteria are nowhere in that model.** They are not observations, so
the guard is not about them; and there is no field that can name them.

That is a gap in scope, not a vacuous field, and it is load-bearing.

## The proof that the gap is real, not theoretical

Ledger sequence 55, subject
`semantic:org.java-websocket.draft6455.server-handshake.response-server-and-date-fields`,
carries `mismatch_class: underspecified-behavior` and this reasoning, verbatim
from its own rationale:

> MISMATCH CLASS underspecified-behavior: RFC 6455 4.2.2 fixes the REQUIRED
> fields and neither requires nor forbids Server or Date, and field order is not
> significant, so **the RFC does not determine this observable at all**.

Every word of that is true. And US-011 AC2 does determine it
(`docs/prd-pack/07b-child-prd-us009-us019.md:33`):

> A valid request emits a deterministic 101 response with the exact
> Sec-WebSocket-Accept, required headers, **no Java-specific Date or Server
> banner**, and a normalized semantic handshake event.

So the observable was recorded as underspecified, DIV-06 then implemented Java's
choice on the strength of that, and a project criterion had forbidden it the
whole time. F010 filed that as a failure of the DIV-06 review to check the story
criterion. **F013 is the upstream half: the ledger record had already concluded
the question was open, using a model in which the criterion could not appear.**
The DIV-06 author was reasoning correctly from a record that was correct within
its own scope.

`underspecified-behavior` reads as "nothing determines this". It means
"RFC 6455 does not determine this". Those differ exactly when a project
specification governs an observable the RFC leaves open — which is precisely the
case the class is most often applied to.

## Extent, measured, and honestly bounded

- `evidence/java/behavior-delta-ledger.json`: **2** records carry the class in
  the ledger's own field, sequences **55** and **56** (49 of the 56 records
  predate the vocabulary and carry no `mismatch_class` at all).
- `evidence/java/legacy-record-adjudications.json`: **20** of the 49 legacy
  adjudications carry `underspecified-behavior` (26 `java-quirk`, 2
  `rust-defect`, 1 deliberately unclassified — sequence 19, the honest
  evidence-does-not-settle-it).
- **22 records total** were classified as underspecified in a model with no slot
  for the project's own criteria.

**I am claiming exposure, not error, for 21 of the 22.** Exactly one — sequence
55 — is *proven* mis-scoped, because AC2 is quoted above and governs it.
Establishing whether the other 21 are affected means reading each subject
against the acceptance criteria of the story that owns its surface, which is
real work and I have not done it. Anyone tempted to report "22 records are
wrong" would be committing the founding defect: a count standing in for a
reading.

## Sequence 55's rationale is also now factually false

Independently of the classification, its opening sentence is stale:

> the port's response omits the Server and Date fields shipped Java adds, and
> does not sort its field names

The port emits both (`rust/ws-core/src/handshake/server.rs:277,:281`) and writes
the five field names in `String.CASE_INSENSITIVE_ORDER`. That is the PRE-fix
state described as current. This is the second stale ledger rationale found in
one day, after the DIV-05 continuation found sequence 34.

The record itself named the mechanism that caused all of this, and named it
correctly:

> whose doc comment cites postProcessHandshakeResponseAsServer as the authority
> for the three fields it writes while that same method writes five — an
> incomplete citation of the cited method, which is why no reviewer caught it

## What is needed, and what I deliberately did not do

Sequence 55 needs a superseding record. I did **not** write one. The mechanism
is a structured `Definition.Supersedes` claim plus a chain regeneration, bound
by `internal/deltaledger.VerifySupersessionsMatchDefinitions` (which exists
because an earlier prose-token version created real withdrawals from *quoted*
tokens). Half-implementing that would leave the chain in a worse state than
leaving it alone, and a parallel branch is tasked with exactly this work.

Note that the supersession does **not** need the F010 owner ruling. The
superseding record can state the current bytes truthfully and keep
`disposition: unresolved` pending that ruling. The factual staleness and the
open question are separable, and conflating them is what keeps the stale
sentence in the tree.

What the ledger needs structurally is a way to say "a project specification
governs this observable", so that `underspecified-behavior` can mean what it
says. That is a schema question — the per-record schema is pinned at 1.0.0
precisely because bumping it rewrites every record digest and the frozen prefix
— so it is an owner decision, not a change to make in passing.

## Status

Filed. One correction to my own hypothesis recorded above rather than deleted.
No ledger record edited, no supersession written, no count re-baselined.
