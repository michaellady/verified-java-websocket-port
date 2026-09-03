# US-022 denominator tooling

Three scripts. None of them is evidence; they are how the evidence in
`../denominator.json` and `../fixtures/` is regenerated and how the checker that
judges it is falsified.

Run all three from the repository root.

## `gen_manifest.py` — regenerate the denominator

```
python3 assurance/mutation/tools/gen_manifest.py .
go run ./cmd/mutdenomctl -emit-payload-digest -root .    # then paste back in
```

Every surface digest in the script came from
`go run ./cmd/mutdenomctl -emit-digest <paths> -root .` and is re-derived from
the tree by `-check`, so a stale digest is a finding rather than a silent
inaccuracy. The payload digest is a fixpoint: `PayloadDigest` blanks
`signature.payload_digest` before hashing, so re-running the emit after pasting
it back yields the same value.

## `gen_fixtures.py` — regenerate the polarity suite

```
python3 assurance/mutation/tools/gen_fixtures.py .
go run ./cmd/mutdenomctl -replay-fixtures assurance/mutation/fixtures/cases.json -root .
```

One green base manifest plus one derived manifest per rule, each carrying a
single mutation. Exactly one case expects OK; the runner refuses a catalog with
no green case, because a suite with none would pass under a checker that blocked
unconditionally.

Cases that attack the signature block are applied *after* signing (`post=`), or
the signer would simply restamp them.

The fixtures are signed with the published, deliberately non-secret key derived
in `cmd/mutdenomctl/fixture_key.go`, and `-sign-fixture` refuses any document
whose id does not begin with `us022-polarity-fixture-`.

## `attack.py` — the deletion attack

```
python3 assurance/mutation/tools/attack.py .
```

**This script edits `internal/mutdenom/check.go` in place.** It backs the file
up first, restores it in a `finally` block, and verifies the restoration is
byte-identical before reporting. Do not run it with uncommitted changes in that
file.

It neuters each BLOCK `add(...)` call site one at a time by wrapping it in
`if false { … }` — never by deleting code, because **a mutation that breaks
compilation proves nothing**: the build failure, not the missing check, is what
turns the suite red. Each neutered checker must turn the polarity suite RED. A
check that stays green when deleted is not evidence.

Exit 0 means every mutation was caught. Any survivor is a check with no witness,
or two checks sharing one finding code so that either can hide behind the other.
The first pass over this package found four; see
`drafts/self-review/us022-mutation-denominator-round-1.md`.
