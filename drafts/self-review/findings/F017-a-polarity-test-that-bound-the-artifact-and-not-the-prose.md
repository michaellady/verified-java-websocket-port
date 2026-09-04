# F017 — a polarity test that bound the artifact, and not the sentence quoting it

## What I did

Merging `claude/handshake-discrimination` (mainline `cdf074f`) raised the
handshake ceiling from 26 to 29 distinct scored observations. I did not accept
the number; I tested it:

> The number is RECOMPUTED, not declared. Set it to 30 and `internal/normcollide`
> fails with "the 49/49 bound does not read the handshake census it cites",
> exit 1. Restored byte-identical.

That test is sound and the conclusion I drew from it was not.

## What it actually established

`evidence/normalization-collisions/audit.json`'s
`handshake_distinct_scored_observations` is bound to the census, so THAT value
cannot drift from what the code measures.

## What I read it as

That the number 29 was safe everywhere it appeared.

`drafts/self-review/normalization-collision-audit.md` — the record a person
actually reads — still said, at lines 109 and 110:

```
- The 49 handshake cases produce only **26 distinct scored observations**.
- **27 of the 49 cases share their observation with at least one other case.**
```

Both stale. The artifact said 29 and 23. The prose said 26 and 27, and the prose
is the half a reader reads.

## Attribution, checked rather than guessed

`git log -S'"handshake_distinct_scored_observations": 29'` names `d90308a`
("normcollide: recompute handshake bounds through the audit's own path"). Its
`--name-only` does not include `normalization-collision-audit.md`: the branch
moved the artifact and left the prose.

**I merged it.** My merge ran the polarity test, read exit 1 on a mutated value,
and stopped there. The prose was never in the test's scope and I did not notice
that it was outside it. The defect is the branch's; shipping it to mainline under
a verification that did not cover it is mine.

## The shape

This is not "I should have tested more". The test I ran was the strongest one
available for what it covered. The error is in the inference: a check proving
`X` in `audit.json` is bound to the code says nothing about a sentence in a
markdown file that also contains `X`. I generalised from "the strongest check
passed" to "the number is right", across a boundary the check does not cross.

The same shape has now appeared four times in this session, three of them mine:
a check exact about the wrong thing (`pinconsumerctl consumers`), a gate whose
PASS I read as an adjudication it never made (F016), a commit message asserting a
file set it verified only along the digest axis (F011), and this.

## The fix, which is not mine

`internal/normcollide/recordbounds.go` — `CheckRecordBounds` and
`CheckRecordSurfaceRow`, from `claude/normalization-collision-closure-2`. It
reads the record's own sentences and compares each stated bound against the
committed document, fail-closed when a claim is absent.

Verified here rather than accepted: setting line 121 back to 26 gives

```
--- FAIL: TestLandingRecordStatesTheBoundsTheDocumentMeasures
    handshake_distinct_scored_observations: record line 121 says 26,
      the committed document measures 29
```

exit 1, naming the line and both numbers; restored, exit 0. It catches exactly
what I shipped.

Its own ceiling, stated by its author and worth repeating: **every other
record's prose is still pinned to nothing.** This binds one record.

## Status

Fixed on that branch and merged. Filed because the reading error is the durable
part: the strength of a check is not evidence about its scope, and I keep
treating it as if it were.
