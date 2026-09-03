# F014 — a code binding verified against a copy of itself

## What the artifact claims

`evidence/java/test-manifest.json`, under
`$.authoritative_run.execution_code_binding`:

```json
"post_run_drift_checked": true,
"material_execution_path_changed_after_run": false,
"sources": [
  {"path": "internal/lab/executor_darwin.go", "digest": "sha256:863bc6d7…", "bytes": 52560},
  {"path": "internal/lab/inventory.go",       "digest": "sha256:f34e5787…", "bytes": 24593},
  {"path": "internal/lab/sandbox.go",         "digest": "sha256:acb7ecd0…", "bytes": 30704},
  {"path": "cmd/labctl/main.go",              "digest": "sha256:7197bfc7…", "bytes": 17306}
]
```

The whole purpose of an execution code binding is to tie a run's evidence to the
code that produced it. This one says, in as many words, that the material
execution path did not change after the run, and that drift was checked.

## What is actually on disk

| path | pinned bytes | actual bytes | digest |
| --- | --- | --- | --- |
| `internal/lab/executor_darwin.go` | 52560 | **55461** | `863bc6d7…` → `9f8c3d0b…` |
| `internal/lab/sandbox.go` | 30704 | **33260** | `acb7ecd0…` → `aef61f2b…` |
| `internal/lab/inventory.go` | 24593 | 24593 | matches |
| `cmd/labctl/main.go` | 17306 | 17306 | matches |

Two of the four material execution sources have drifted, by 2901 and 2556 bytes.
Two independent signals agree — the digest and the byte count — so this is not a
line-ending or whitespace artifact. `material_execution_path_changed_after_run:
false` is false.

## Why nothing caught it

`internal/lab/evidence.go:666` hardcodes the expected binding as a Go literal:

```go
expectedSources := []evidenceSourceBinding{
    {"internal/lab/executor_darwin.go", "sha256:863bc6d7…", 52560},
    …
}
for index := range expectedSources {
    if binding.Sources[index] != expectedSources[index] {
```

The check compares **the manifest's declaration against a second declaration of
the same numbers in the source code**. It never opens
`internal/lab/executor_darwin.go`. Both copies can agree perfectly — and they
do — while the file they describe has changed underneath both.

`schemas/java-test-manifest-1.0.0.schema.json:20` closes the loop:
`"post_run_drift_checked": {"const": true}` and
`"material_execution_path_changed_after_run": {"const": false}`. Those are
`const` in the schema, so the manifest is *required* to assert that no drift
occurred. The document cannot express the drift that has occurred, and nothing
in the repository recomputes it.

So all three layers agree, and all three are describing a state of the world
that has not held since `93f5444`.

## The class

This is the project's founding defect class — existence standing in for identity
— specialised to digests: **two declarations agreeing, standing in for the thing
they describe being unchanged.** It is the same shape as F011 (a claim checked on
the axis its author was thinking about) and F008 (the nearest explanation
standing in for the diagnosis), but in the worst possible location: the artifact
whose only job is to bind evidence to code.

Worth stating plainly, because it is the part that would be easy to soften: the
check is not weak. It is exact, it is byte-for-byte, and it is verifying the
wrong pair of things.

## How it was found

`cmd/pinconsumerctl dangling`, on its first census run over the tree — 1996 JSON
artifacts, 86 candidates. This was candidate 2 and 3.

The tool indexes by digest VALUE rather than by key name, because the tree pins
paths under at least twelve different keys (`path`, `reportfile`, `file`,
`manifest_path`, `source_path`, `catalog_source_path`,
`mutation_manifest_path`, `source`, `target_path`, `pin_file`,
`lifecycle_path`, `adapted_path`). A schema-aware parser would have missed this
one the moment a thirteenth key appeared.

## What it does NOT establish

The manifest may well have been true when it was written. If the authoritative
run happened while those files carried the pinned digests, the record was honest
at the time and the drift is later. Nothing here shows the run was invalid, and
this finding does not claim it.

What it establishes is narrower and still serious: the claim is **unbound**. No
check would notice whether it were true or false, so its being false today was
never going to be detected, and its being true tomorrow would be luck.

## Owner decision, because re-pinning would be the substitution this repository keeps filing

Two defensible resolutions, and I am deliberately not choosing:

1. **The binding is stale and the run must be redone.** That is a lab run and
   therefore an owner gate — not triggered here.
2. **The drift is immaterial to the run** (the changed bytes are not on the
   material execution path). Then the manifest is re-pinned WITH that rationale
   recorded, and the schema stops pinning
   `material_execution_path_changed_after_run` to `const false` so that a future
   drift can be stated instead of being unrepresentable.

Silently re-pinning the digests to make the check pass would convert a false
claim into a true-looking one without measuring anything, which is exactly what
this finding is about.

**What must change regardless of which is chosen:** the check must recompute
from disk. A binding verified against a copy of itself is not a binding.

## Status

Filed, not fixed. Measured with `sha256sum` and `wc -c`, both quoted above. The
detector that found it is committed with this finding and carries this case as a
regression-protected calibration fixture, so the drift cannot silently widen.
