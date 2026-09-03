# Supersession is a third state, and the census could not name it

## What prompted this

The record census reported exactly one unfinished record in the tree:
`drafts/self-review/normalization-collision-audit-WIP.md`. I read that as
outstanding work and wrote an agent brief telling it to settle whether the file
was "a superseded orphan of an earlier branch", to be resolved item by item, and
to rename it if the items were closed.

Then I read the file. Its last four lines say:

> **SUPERSEDED** by `drafts/self-review/normalization-collision-audit.md`.
> This file is kept unedited because it records the reading I had mid-audit —
> including the "six top-level keys" claim, which the landing record corrects to
> four (`role` and `initial_state` are request echoes recoverable from
> `request_digest`, so their absence cannot hide a behaviour).

It is not an orphan. It is deliberately retained, unedited, to preserve an
intermediate reading that the landing record corrects — which is exactly the
practice this repository should want, and the opposite of what I was about to
have someone do to it. The agent I briefed died on an API error before acting,
which is the only reason the brief did nothing.

`recordguardctl` had zero occurrences of "supersed" anywhere in it. The tool was
right that the record does not read as finished, and had no way to say why that
was correct.

## What the tool does now

A third state. `Supersession(path)` returns the named target, whether the claim
holds, and if not, which of two ways it failed.

```
gate=record-content-precondition census SUPERSEDED record=drafts/self-review/normalization-collision-audit-WIP.md signals=2 superseded_by=drafts/self-review/normalization-collision-audit.md
    not unfinished work: the record says it was replaced, and the named record exists and reads finished. Retained on purpose.
gate=record-content-precondition step=census records=48 unfinished=0 superseded=1 finished=47
```

The tree now reads as having **zero** unfinished records and one deliberately
retained superseded one. Previously it read `unfinished=1`, which is the number
that misled me.

A superseded record is **still refused** as a landing precondition — a landing
decision must never name a withdrawn document as its review — but the verdict
and the remedy differ:

```
verdict=REFUSED-SUPERSEDED superseded_by=drafts/self-review/normalization-collision-audit.md
   this record declares itself superseded and the claim CHECKS OUT: ... exists and
   itself reads finished. It is deliberately retained, not unfinished work. Name
   the superseding record instead of finishing this one.
```

## The property that keeps this from being an escape hatch

This tool's own measured ceiling is that self-declarations bind honest authors
and nothing else: strip the self-declarations from the six historical stubs and
only 1 of 6 is still caught. A state reachable by writing one sentence about
yourself would therefore be reachable by any record that wanted it — and it
would be the *good* state, which is worse.

So the declaration is necessary and not sufficient. Two further conditions are
checked against the filesystem:

1. the named record **exists**, resolved relative to the declaring record's
   directory and then to the root; and
2. the named record **itself reads finished**, by the same `Scan`.

Condition 2 is load-bearing: without it a stub could be excused by pointing at
another stub, and a cycle of mutual supersessions would launder every record in
it. It is pinned by a fixture whose target is a stub, and by deletion attack A1.

## Deletion attacks: five, all `false &&`, and two rounds because the first was wrong

A mutation that breaks compilation proves nothing, so every attack keeps the
source compiling and is skipped and labelled if it does not.

**First round produced three misleading results and I am recording all three
rather than the tidy second round alone.**

- `go test` served a **cached** result. A mutation was applied, the test
  reported `ok (cached)`, and my harness scored that as SURVIVED. Every attack
  in that round was worthless. Fixed with `-count=1`. An exit code from a test
  that did not run is not an exit code.
- One "SURVIVED" was an **anchor miss**: the `sed` expression did not match, so
  the source was never mutated. The harness now fails loudly on a missed anchor
  instead of scoring it.
- One attack was a **build break** (`if false {` left `masked` and `i` unused),
  correctly labelled as proving nothing and rewritten as
  `if false && (original condition)` so the variables stay referenced.

Second round, with `-count=1` and verified anchors:

| attack | result |
| --- | --- |
| A1 the target-must-read-finished conjunct dropped | caught |
| A2 the quoted/fenced-voice exclusion dropped | **SURVIVED** → fixed, now caught |
| A3 the target-existence guard dropped | **SURVIVED** → fixed, now caught |
| A4 reason swap, unfinished → missing | caught |
| A5 reason swap, missing → unfinished | caught |

Both survivors were real defects, not gaps in the attack.

### A3: the existence guard was redundant, and the redundancy was a wrong message

Dropping `if err != nil { continue }` on the target read changed nothing. A
missing file reads as an **empty document**, an empty document trips
`cites-nothing`, and so the claim failed anyway — by accident, and with the
wrong explanation. A record whose supersession path had a typo was being
reported as pointing at an *unfinished* record. Its author would have been told
to go and finish a file that does not exist.

Fixed by returning and printing which of the two failures occurred, so the
branch is observable and A3 is caught. The two reason strings are pinned apart
by a test that also asserts they are not equal, because if they were equal the
distinction would be unobservable and the guard would go slack again.

### A2: my quotation test passed for the wrong reason

I had a case asserting that a supersession inside a block quotation does not
count. It passed — but on the **regex anchor**, not the voice exclusion: a
leading `>` is not in the allowed leading-marker class, so the pattern never
matched that line at all. The voice exclusion was unproven, and A2 surviving is
what proved it unproven.

What the exclusion actually protects is a **fenced** example: inside a code
fence the line is character-identical to a real declaration, and nothing in the
anchor rejects it. That is the case a record documenting the convention — or
quoting another record's ending — would hit. Added as a fixture, and A2 is now
caught. The block-quotation case is kept, with a comment saying it rests on the
anchor and does not bind the exclusion.

## An implementation detail worth recording

`maskOtherVoices` blanks quoted and fenced lines wholly AND blanks inline code
spans within ordinary lines. The supersession path lives inside such a span, so
matching the masked text finds nothing — my first implementation returned `false`
on the real record for exactly that reason. The mask is therefore used only to
decide **whose voice** a line is in: a line the mask empties entirely was a
quotation or a fence; otherwise the raw line is matched.

## Exit codes, read from the process

```
go build ./cmd/recordguardctl/                      exit 0
go test -count=1 ./cmd/recordguardctl/              exit 0
go run ./cmd/recordguardctl gate -root .            exit 0
  selfcheck cases=14 firing=6 silent=8 result=PASS
  census records=48 unfinished=0 superseded=1 finished=47
precondition on the retained record                 exit 1, REFUSED-SUPERSEDED
make -C rust gates                                  exit 0
scan.go restored byte-identical after all attacks   sha256 97bb44b2ecea3a0b…
```

## What this does not claim

The three conditions bind a record that is *honest about being replaced*. A
record that wanted to be misread as superseded would have to point at a real,
finished record — a much higher bar than a sentence, but not a proof of intent,
and nothing here detects a supersession that is real but wrong (a record
withdrawn in favour of one that does not actually cover it). That is a reading
task, not a check.

One existing assertion changed: `main_test.go` pinned the census substring
`"unfinished=1 finished=1"`, which the new `superseded=` field breaks. Updated to
`"unfinished=1 superseded=0 finished=1"` — same strength, new format, not
weakened to a looser match.

## A false positive the tool found on this very record, and why I did not fix it

My first title was:

> # A retained record is not unfinished work, and the census could not tell

`recordguardctl precondition` refused it, exit 1, one signal:

```
line=1 signal=declared-title term="unfinished" | # A retained record is not unfinished work, and the census could not tell
```

That is a **false positive**. The title *discusses* unfinishedness and in fact
negates it; it does not declare the record unfinished. `declared-title` matches
the term anywhere in the title.

I could have narrowed the rule. The four historical stubs that fire on title all
put the term in a trailing qualifier:

```
# catalog plane correspondence — working notes (WIP)
# Concurrency coverage disclosure — WIP
# Legacy record adjudication — WORK IN PROGRESS
# Rank 3 independence — work in progress
```

Mine had it at word seven of thirteen, mid-clause, under a negation. A
position-or-trailing-segment rule would separate them.

**I did not do it, and the reason is the incentive.** I would have been
narrowing a detector calibrated on six real records so that MY document passes
it. That is the wrong direction to change a check from, whatever the merits, and
the merits are not clear either: negation detection is trivially gamed ("this is
not a stub", on a stub), and a position rule invites `# WIP — notes` becoming
`# Notes, and they are WIP so far` to slip through.

The tool also has a point I would rather concede than engineer around. In a
repository where "unfinished" is a *status*, putting the word in a title does
invite exactly the misreading this record is about. `# Supersession is a third
state, and the census could not name it` is a better title on its own merits.

So: retitled, and the false positive recorded here rather than silently worked
around. The next person to write about unfinishedness will hit it, and should
know it is a known limit of the rule and not a judgement about their record. If
it recurs, the trailing-qualifier narrowing above is the change to consider —
made by someone whose own document is not the thing being unblocked.

## Correction to a brief I wrote

The agent brief that called this file "a superseded orphan" to be settled item
by item was wrong on the facts. The file settles it in its own last four lines,
and the item-by-item comparison it asked for was work the record had already
done. Recorded here because the brief is in this session's history and someone
may read it.
