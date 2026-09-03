# `covered=` — a declared exemption, kept honest by reading the check it names

## The problem

After the candidate adjudication, `pinconsumerctl dangling` reported 34 rows: 9
true findings and **25 false positives a human had already adjudicated but the
code did not know about**. 22 of those were one class, all in
`assurance/replay/fixtures/us006-cases.json`.

A census that is 73% noise gets ignored, and then the 9 true rows go unread.

## Why they could not simply be `explained`

Every existing subtraction is a RECOMPUTATION: the tool re-derives the digest
from current bytes and proves it covers something other than the named file. That
is why those rules cannot go quiet when a real pin drifts.

The us006 rows cannot be done that way. The object is:

```json
{
  "id": "us006-good-backend-executed",
  "mutation_manifest_path": "…/us006-good-backend-executed/mutation.json",
  "realized_tree_sha256": "sha256:7eebd5f5…"
}
```

`realized_tree_sha256` is `CANONICAL_PATH_SHA256_V1` over the tree **produced by
applying** that manifest — not a digest of the manifest. Recomputing it means
realizing the tree, which is what `us006RealizeCase` does inside
`internal/formalplan`'s test. Duplicating that in a production tool would be
copying test logic; keying on the field NAME instead would be exactly the
name-keyed rule the previous round rejected, and it would keep reporting a row as
explained after the thing that made it explicable had changed.

## What was done instead

A third class, `covered=`, distinct in kind from `explained=` and labelled so it
cannot be read as one.

A coverage claim names the artifact, the pointer prefix, **the file containing
the covering check, and a literal assertion from it**:

```
artifact:      assurance/replay/fixtures/us006-cases.json
pointerPrefix: $.cases[
checkFile:     internal/formalplan/backend_test.go
assertion:     "realized digest %s != frozen %s"
```

That covering check is the strongest kind available — `backend_test.go:936`
realizes every case, recomputes the canonical tree digest and fails on mismatch,
naming `US006_REGENERATE=1` as the deliberate refreeze path. As of the `go-suite`
target it now runs inside `make -C rust gates` rather than beside it.

`verifyCoverage` reads that assertion back **on every run**. This is the whole
mechanism: a claim cannot outlive the check it names.

## The polarity that makes it honest, read from the process

Changing the covering assertion in `backend_test.go` from
`realized digest %s != frozen %s` to `realized digest %s differs from frozen %s`:

```
gate=pin-dangling finding=STALE_COVERAGE_CLAIM detail="…backend_test.go no longer
  contains the covering assertion \"realized digest %s != frozen %s\""
gate=pin-dangling json_artifacts=1996 unparsable=0 candidates=34 explained=51 covered=0
gate=pin-dangling result=FAIL reason="a coverage claim names a check that is no
  longer there; the exemption outlived the check and every row it covered is
  unverified"
```

exit 1. **All 22 rows come back as candidates and the gate fails.** They are not
silently exempted. `backend_test.go` restored byte-identically, `diff -q` clean.

With the check in place: `candidates=12 explained=51 covered=22`.

## Four tests

- every declared coverage claim names a check that exists (run against the real
  tree, so it is checked on every run rather than when someone looks);
- a covering file that no longer carries its assertion IS reported stale — or the
  guard above is decorative;
- every claim clears a 120-byte floor on why it cannot be recomputed here, and
  leaves no field empty;
- coverage does not reach beyond its declared prefix or artifact — a covered row
  must still correspond to a real candidate.

## What this is NOT, stated because the distinction is the whole point

`covered=` is a claim about **someone else's check**, not a measurement here.
"Another layer would notice" was rejected earlier in this project and rightly;
the difference is that this names the layer, names the assertion, and fails when
the assertion goes away. That is weaker than `explained=` and the ceiling text
now says so in those words, so the two counts cannot be added together and read
as one number.

The 11 that remain are the 9 true pins (3 `denominator_basis` whose anchor is not
an ancestor of HEAD — a denominator, hard stop; 2 pinning bytes in no branch; 2
dated attestations; 2 F014) plus 3 singletons not yet read.

## Readings

- `go test ./cmd/pinconsumerctl/` exit 0, 25 tests.
- `dangling` before: `candidates=34`. After: `candidates=11 explained=51 covered=23`.
- Stale-claim path: exit 1, `result=FAIL`, `covered=0`, `candidates=34`.
- One build failure on the way (`undefined: moduleRoot`, then a duplicate
  `repoRoot` helper) — build failures, which prove nothing and are recorded as
  such rather than as findings.


## A second coverage claim, and the same mechanism generalising

Reading the three singletons left in the census found one more of the same shape.
`evidence/java/legacy-record-adjudications.json` `$.adjudications[12]` carries
`record_digest` beside `supersession_draft`, and the detector read the digest as a
pin of that draft. It is not: `record_digest` is the digest of LEDGER RECORD 13,
and the value is in `evidence/java/behavior-delta-ledger.json` — a DIFFERENT
file, which is exactly why `pinsAFieldInside` cannot see it, since that rule only
looks inside the named file.

The covering check is `internal/deltaledger/legacy_adjudication.go`:

    the entry binds record_digest %s; the record digests to %s

which recomputes every record's digest from its own bytes. Declared as a second
coverage claim; `candidates` 12 -> 11, `covered` 22 -> 23.

## A rule I tried and the test suite refused

The last two candidates are fixtures declaring `1111…1111` and `aaaa…aaaa`. I
added a rule — R6 — exempting any digest using two or fewer distinct hex
characters, on the reasoning that no real sha256 does, and that the property is
judged from the VALUE rather than a field name, so it could not be aimed at a
particular fixture.

**It was wrong, and the existing suite caught it immediately.** Three tests
failed:

```
TestAnalyseDanglingReportsAStalePinAndItsPointer
  expected exactly one candidate, got 0
TestFieldProvenanceIsExplainedOnlyWhenTheFieldActuallyMatches
  an unverifiable field claim must stay a candidate, got []
TestAnUnexplainedDigestIsNotCoveredByAnExplainedNeighbour
  an object with one unprovable digest must stay a candidate
```

Those tests build their fixtures with digests like `cdcd…` and `1111…` **to
represent a genuinely stale pin**. So repeated-character digests are precisely
how this project writes "a real drifted pin" in a fixture, and my rule would have
made that shape invisible — including in the tests whose job is to prove drift is
caught.

R6 and its helper are reverted. The two rows stay candidates. Their explanation
belongs in a record a human wrote, not in a rule, which is the same conclusion the
previous round reached about the 22 and it was right both times. A smaller number
would have been worse.

Final: **`candidates=11 explained=51 covered=23`** — 9 true pins and 2 fixtures
whose mismatch is their assertion.

## The finding this firing actually turned up: the census gates nothing

Making the census readable is worth little if nobody is obliged to read it, and
that is the state today. `grep -n pinconsumer rust/Makefile` returns nothing:
**`pinconsumerctl` is not in the gates chain.**

Its 25 TESTS do run there, because `cmd/pinconsumerctl` is a package and
`go-suite` runs every package it does not exclude. So the detector's own
behaviour is gated. What is not gated is its VERDICT: `dangling` exits 1 with 11
candidates right now, `make -C rust gates` exits 0, and both statements are true
at the same time.

Concretely: **F014 is a real drifted pin — `evidence/java/test-manifest.json`
declares digests for two `internal/lab` sources that no longer match — and
nothing fails because of it.** A pin that drifts tomorrow would be equally
invisible. That is the same shape as the `internal/deltaledger` hole this session
already closed: a check exists, runs, reports, and gates nothing.

Not fixed in this firing, deliberately, and the reason is not that it is hard.
Wiring `dangling` in as-is would turn gates red immediately on the 9 true pins,
every one of which is BLOCKED on something outside the loop's reach: 3
`denominator_basis` rows whose anchor is not an ancestor of HEAD (a denominator —
a hard stop, never re-baselined), 2 pinning bytes present in no branch, 2 dated
attestations that would be falsified by rewriting, and F014's 2, which is an
owner decision. Halting the loop on those would not fix them.

The shape that would work is the one this firing already built twice: a declared
allowance listing exactly those 9 rows with the owner action each waits on, so a
NEW drift fails the gate on the run it appears, while the known-blocked set does
not halt anything — and, as with `STALE_COVERAGE_CLAIM` and `STALE_EXCLUSION`, an
allowance for a row that has since been fixed must itself fail. That is a unit of
its own and it is named here so it is not lost.

Until then, this is the honest statement: the pin census is INFORMATIONAL, `make
-C rust gates` does not read it, and a drifted pin does not fail anything.
