# F020 — a measurement whose enumerator was deleted

STATUS: RECORDED, and the half that could be repaired has been.

## The finding

The US-019 survivor round published a site enumeration of **110** `if`
conditions across the four non-test files of `internal/autobahnsuite`. A
`go/ast` walk over those same four files returns **111**:

| file | if-conditions |
| --- | ---: |
| `baseline.go` | 43 |
| `independence.go` | 16 |
| `reconcile.go` | 27 |
| `suite.go` | 25 |
| **total** | **111** |

The off-by-one is not the finding. **The finding is that nobody can check the
110.** Round 4's enumerator was `.sweep/mutate.py`, and `.gitignore:80` ignores
`.sweep/`; the directory does not exist in this tree. The number was published,
the tool that produced it was never committed, and the two facts together mean
the published figure is unfalsifiable — it cannot be reproduced, and it cannot
be shown wrong either, only disagreed with.

That is worse than an incorrect number. An incorrect number that re-derives
gets corrected the first time someone runs the derivation. A number with no
derivation survives every review, because there is nothing to run.

## What was NOT done

Round 4's numbers are left exactly as recorded. Nothing was re-baselined, and
the 110 is not edited to 111 anywhere. A published measurement is corrected by
supersession here, and this record is that supersession.

The count is also deliberately **not bound** to a gate. Binding it would fail
the build every time somebody adds an `if` to a file that has nothing to do
with the survivor sweep — a treadmill that punishes ordinary work, and a
denominator invented from inside a fix. The problem was never that 111 was
unenforced; it was that 110 was uncheckable.

## What changed, and why the repair was possible

Until the US-019 line landed, `internal/autobahnsuite` did not exist on
mainline at all, so **neither** number could be re-derived here — the sources
were on a branch nobody could merge. With the line landed, the inputs are
present, and the method is a plain walk of every `*ast.IfStmt` with a non-nil
`Cond` over the four non-test files of that package. Anyone can now reproduce
the 111 from the tree, in a few lines, without this repository shipping a tool
for it.

So the repair is not an assertion and not a script. It is that the *inputs*
are now permanently present and the *method* is stated precisely enough to be
run by someone who does not trust this record.

## The general shape, which outlives US-019

A measurement is only as durable as the thing that produces it. Three
conditions have to hold for a published figure to remain checkable, and this
one failed all three at the time it was written:

1. the **inputs** are committed — they were on an unmergeable branch;
2. the **method** is recorded precisely enough to re-run — "the enumerator"
   named a file nobody had;
3. the **tool**, if the method is not trivially restatable, is committed —
   `.sweep/` is gitignored.

Meeting any one of the three is enough. This repository already leans on (1)
and (2) everywhere its gates re-derive rather than re-read, which is why those
gates survive review; the survivor round leaned on (3) alone and then ignored
the tool.

## Ceiling

This record establishes the 111 for the four files it names, at this commit. It
says nothing about the other populations that round's sweep enumerated — the
switch arms, the Rust-side decision points and the conjuncts — whose own
enumerations rest on the same deleted tool and have not been re-derived here.
Those remain published figures that nobody has independently reproduced.
