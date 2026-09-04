# Bringing the formal denominator's basis artifacts onto this line

Owner ruling `OA-catalog-plane-denominator`, 2026-09-04:

> BRING THE BASIS ARTIFACTS ONTO THIS LINE. Copy the artifacts anchored at
> 1ff89fa into this plane and re-anchor the three denominator_basis pins to a
> commit that IS an ancestor of HEAD. This moves the formal denominator's
> declared basis, so the before/after must be REPORTED side by side and never
> absorbed silently.

**Verdict.** The first clause was executed for the one pin where it could be
executed without destroying something: the artifact that existed in no commit on
this line is now on it, byte-identical to the blob its pin declares. The first
clause is REFUSED for three of the other four, with measurements below: the
artifacts at that anchor under those paths are not older versions of this line's
files, they are different documents, and one of them makes the whole
formal-coverage derivation refuse. The second clause is REFUSED for all five,
because no pin can be re-anchored without editing the byte-immutable vendored
catalog, and that is raised as `OA-basis-anchor-vs-catalog-immutability` rather
than absorbed. The vendored catalog was not edited. Its identity is unchanged.

Assurance: OWNER_ATTESTED_NOT_INDEPENDENT. No independent review is claimed. No
owner-gated lane was run: no AWS, no benchmark, no Autobahn, no `internal/lab`.

## 1. The pins, and what each really was

The ruling and the plan node both say *three*. **Five** entries of
`$.denominator_basis` name commit `1ff89fa30cb0ab6ff339afd3ce486a36e9f7f325`,
and `git merge-base --is-ancestor` puts that commit outside this line's history
(exit 1). It is also not confined to `origin/codex/race-catchup`:
`git branch -a --contains` lists ten `origin/codex/*` refs. Nothing was written
to any of them.

The *three* is exact, and it is pin-guard's: `cmd/pinconsumerctl/main.go`
declares an allowance for `$.denominator_basis[1]`, `[3]` and `[4]`, each
reading `DENOMINATOR, HARD STOP`, plus their three mirrors in the
reconciliation. Those are the pins that census can SEE. The other two are
invisible for two different reasons, and only one of those reasons is the
missing-artifact one the ruling is about.

| # | path | pinned blob is on this line? | state before | why pin-guard did or did not see it |
|---|------|------------------------------|--------------|--------------------------------------|
| 0 | `assurance/developer-tools/port-seam-dossier.json` | yes, at ancestor `93f5444` | `BASIS_PIN_MATCHES_FILE_ON_DISK` | not a candidate: the declared digest IS the file's current digest |
| 1 | `assurance/formal/proof-targets.json` | no | `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK` | candidate, allowed, `DENOMINATOR, HARD STOP` |
| 2 | `corpora/frame/codec.json` | no, and the path was in no commit here | `BASIS_PIN_PATH_IS_ABSENT_FROM_THIS_PLANE` | invisible: bypass C9b, the target path was untracked, `OA-pin-path-corpus` |
| 3 | `evidence/intake/compatibility-surface.json` | no | `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK` | candidate, allowed, `DENOMINATOR, HARD STOP` |
| 4 | `evidence/intake/semantic-id-migration-map.json` | no | `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK` | candidate, allowed, `DENOMINATOR, HARD STOP` |

"Pinned blob is on this line" was measured, not assumed: for each pin, every
commit in `git log HEAD -- <path>` was resolved to its blob at that path and
compared with the declared blob. Pin 0 matched at `93f5444`. Pins 1, 3 and 4
matched nowhere. Pin 2's path has no commit on this line at all — `git log --all`
finds it on two commits, none of them ancestors of HEAD.

All five artifacts DO exist at `1ff89fa`, each at exactly the declared blob and
the declared sha256. The ruling is therefore not blocked by a missing artifact.
It is blocked by what copying three of them would do here, and by where the pins
live.

## 2. Before, measured without writing into the tree

`formalcoverctl verify` exited 0 on the untouched tree: the retained artifacts
were what the evidence derives. The counterfactuals in section 5 were derived in
a scratch tree unpacked with `git archive HEAD`, so nothing below required
writing a measurement into the repository to take it.

## 3. Before and after, side by side

Every field of the reconciliation was compared, not a summary of it. Three
fields moved. They are all in one object.

| field | before | after |
|-------|--------|-------|
| `catalog_declared_basis_pins[2].path` | `corpora/frame/codec.json` | unmoved |
| `catalog_declared_basis_pins[2].catalog_declared_sha256` | `sha256:984e59e8…b1b4d606` | unmoved |
| `catalog_declared_basis_pins[2].catalog_declared_git_blob` | `da9a7d07…2849fdef6` | unmoved |
| `catalog_declared_basis_pins[2].on_disk_sha256` | `PATH_ABSENT` | `sha256:984e59e8…b1b4d606` |
| `catalog_declared_basis_pins[2].on_disk_git_blob` | empty | `da9a7d07…2849fdef6` |
| `catalog_declared_basis_pins[2].agreement` | `BASIS_PIN_PATH_IS_ABSENT_FROM_THIS_PLANE` | `BASIS_PIN_MATCHES_FILE_ON_DISK` |

And every other field, unmoved:

| field | before | after |
|-------|--------|-------|
| `counts.obligations` | 24 | 24 |
| `counts.proof_targets` | 10 | 10 |
| `counts.obligations_mapped_to_at_least_one_target` | 11 | 11 |
| `counts.obligations_with_no_proof_target` | 13 | 13 |
| `counts.targets_named_by_at_least_one_obligation` | 6 | 6 |
| `counts.targets_named_by_no_obligation` | 4 | 4 |
| `counts.catalog_distinct_java_keys` | 15 | 15 |
| `counts.proof_target_distinct_java_keys` | 27 | 27 |
| `counts.java_keys_in_both` | 5 | 5 |
| `counts.java_keys_catalog_only` | 10 | 10 |
| `counts.java_keys_proof_target_only` | 22 | 22 |
| `counts.property_claim_references` | 11 | 11 |
| `counts.distinct_property_claim_references` | 11 | 11 |
| `counts.planned_production_symbols` | 21 | 21 |
| `counts.planned_symbols_resolver_verified` | 0 | 0 |
| `counts.migration_bindings` | 98 | 98 |
| `counts.migration_bindings_rust_identity_verified` | 0 | 0 |
| `counts.catalog_rust_binding_rows_whose_source_path_is_absent` | 24 | 24 |
| `counts.catalog_rust_binding_rows_whose_namespace_is_absent` | 24 | 24 |
| `counts.catalog_rust_binding_rows_measurable_on_this_plane` | 0 | 0 |
| `shared_java_anchor.agree` | true | true |
| `shared_java_anchor.catalog_java_binding_archive_sha256` | `sha256:f44e7647…` | unmoved |
| `shared_java_anchor.proof_target_quarantined_archive_sha256` | `sha256:f44e7647…` | unmoved |
| `shared_java_anchor.catalog_distinct_java_source_digests` | 1 | 1 |
| `shared_java_anchor.proof_target_distinct_java_file_digests` | 6 | 6 |
| `catalog.sha256` / `catalog.git_blob` | `sha256:21112518…` / `be929320…` | unmoved |
| `proof_targets.sha256` / `proof_targets.git_blob` | `sha256:0f514b0c…` / `faa0be0a…` | unmoved |
| `plane_correspondence.sha256` | `sha256:ca9754be…` | unmoved |
| basis pins 0, 1, 3, 4 (all fields) | as section 1 | unmoved |

The US-023 report moved in exactly one value, twice in the JSON and once in the
Markdown: the reconciliation's own digest, `sha256:98ecba53…` to
`sha256:0cb3326b…`, because the reconciliation's bytes changed. Every ratio the
report carries is unmoved: java_coverage 0/24, rust_coverage 0/24,
paired_comparable_coverage 0/24, production_linkage_java 6/24,
production_linkage_rust 0/24, refinement_coverage 0/24, bound_parity 0/24, both
counterexample_sensitivity axes 6/24 and 0/24, aggregate 0/24,
blocking_obligations 24/24, resolver-verified 0/24.

Gate censuses, before and after:

| census | before | after |
|--------|--------|-------|
| `formalcoverctl verify` exit | 0 | 0 |
| `verify` census lines | one `basis_pin_path_absent_from_this_plane` line | that line gone, nothing else changed |
| pin-guard `json_artifacts` | 3500 | 3501 |
| pin-guard `candidates` / `explained` / `covered` / `allowed` / `missing_targets` | 0 / 53 / 23 / 15 / 0 | unmoved |
| pin-guard result | PASS | PASS |
| plan-guard result | PASS | PASS |
| plan-guard census | nodes=46 done=26 ready=6 blocked=14, owner_actions=29 open=19 | nodes=47 done=27 ready=5 blocked=15, owner_actions=30 open=20 |
| record-guard prose result | PASS | PASS |

## 4. Which numbers moved, and why each was the authorised move

Three fields moved, all of them the *observed* half of one pin, and none of them
the *declared* half. The declared sha256 and the declared git blob of every one
of the five pins are byte-for-byte what they were. Nothing was re-pinned; an
artifact arrived.

* `on_disk_sha256`, `on_disk_git_blob` and `agreement` on pin 2 moved because
  `corpora/frame/codec.json` was written into the tree at exactly the blob the
  pin declares. `git hash-object` returns `da9a7d0734b9db12a44e123ff1c33df2849fdef6`
  and `sha256sum` returns `984e59e8533d909bd50c9042bfc1a7503cdc098e5be4e32f287be140b1b4d606`,
  which are the two values the catalog already declared. This is the ruling's
  first clause, executed literally, for the only pin whose artifact was absent.
* Nothing else could move, and the derivation says so: `reconcile.go` computes
  its counts from the catalog and the proof-target plan, and neither of those
  files was touched. The unmoved column above is the check, not the claim.
* pin-guard's artifact census moved by one because the corpus is `git ls-files`
  and a tracked file was added. Its candidate, explanation, coverage and
  allowance figures are all unmoved, so no finding appeared, none disappeared,
  and no allowance was orphaned.

Nothing moved that the ruling did not authorise. The one thing that would have
moved without authorisation — the vendored catalog's own identity — did not,
because the catalog was not edited.

## 5. What was refused, with the measurement behind each refusal

**Copying the artifacts at `1ff89fa` over pins 1, 3 and 4.** Those three paths
already exist here with different bytes, so "copy the artifact in" means
overwrite. Measured in a scratch tree:

* `assurance/formal/proof-targets.json` at that anchor is not an older version
  of this line's plan, it is a different document. Its top-level keys are
  `plan_id`, `source_basis`, `required_consumers`; this line's are
  `document_id`, `sources`, `rust_identity_resolution`. It declares schema
  1.1.0 against `../../schemas/formal-proof-targets-1.1.0.schema.json`, a file
  this plane does not carry. It holds two targets where this line holds ten.
  With it in place, `formalcoverctl verify` exits 1 at
  `proof-target document id is "", not formal-proof-targets.us006`. The diff
  against HEAD is 1779 insertions and 211 deletions in the other direction, so
  copying it in also deletes the US-006 refreeze that landed at `4ccf415`.
* `evidence/intake/semantic-id-migration-map.json` at that anchor declares
  schema 1.1.0 and cites
  `../../schemas/semantic-id-migration-map-1.1.0.schema.json`, which this plane
  does not carry either; `internal/portplan/schema.go` pins the 1.0.0 schema
  this line's document declares. Row count is the same on both sides.
* `evidence/intake/compatibility-surface.json` is the one that is shape
  compatible: same keys, same item and exclusion lengths, schema 1.0.0 on both
  sides. Copying it in reverts twelve insertions and six deletions made by
  `93f5444`.

A scratch tree with pins 3 and 4 reverted and pin 2 added does derive: every
basis pin then reads `BASIS_PIN_MATCHES_FILE_ON_DISK` and no count moves. That
is worth stating plainly, because it means the price of clause one for those two
is not a moved denominator — it is reverting landed work and importing a
document whose schema this plane does not have. That is a corpus decision, not a
gate fix, and it is outside what the ruling priced.

**Re-anchoring any pin.** The pins live inside
`assurance/formal/obligation-catalog.json`, which is vendored byte-identically
from the Codex plane. Measured: rewriting the `git.commit` and `git.tree` of all
five pins to this line's HEAD changes 395 bytes and moves the catalog from
`sha256:21112518…`/`be929320…` to `sha256:d0258b8a…`/`e10ec7b6…`. With that
file in place `formalcoverctl verify` exits 1 at
`the catalog on disk is … not the vendored Codex catalog`. Landing it would
require editing the two asserted constants in
`internal/formalcoverage/identity.go` — which the file says exist "so a silent
revendoring fails" — the `Codex original` assertion in
`internal/javabind/coverage_test.go`, and the catalog identity pinned in
`assurance/formal/plane-correspondence.json`,
`assurance/formal/catalog-correction-proposal.json`,
`assurance/formal/java-binding-spec.json`, the reconciliation,
`evidence/java/formal-bindings/coverage-projection.json`,
`evidence/java/formal-bindings/receipt.json` and both US-023 report files.

`assurance/formal/catalog-correction-proposal.json` states the rule with four
reasons and sets `this_document_modifies_the_catalog` to false, one of them
being that editing a vendored artifact "breaks the only check that can detect
drift from the plane it came from: byte equality". Its last reason is that
adoption "is an owner decision with a blast radius this branch cannot see". The
ruling does not mention the catalog's byte identity or those constants, so I
have raised the conflict as `OA-basis-anchor-vs-catalog-immutability` rather
than deciding it here. The plane-correspondence record's own owner question
already lists re-vendoring the catalog as option (b), and records that no row in
it reaches `ESTABLISHED_BY_OWNER_DECISION`.

There is also a reading under which nothing needs re-anchoring at all, and pins
0 and 2 now demonstrate it: `git.commit` is provenance — where these bytes came
from — and once the bytes are on this line the pin verifies here without the
anchor being rewritten. Both of those pins name `1ff89fa` today and both read
`BASIS_PIN_MATCHES_FILE_ON_DISK`. `reconcile.go` compares sha256 and blob and
never reads the commit. That reading is offered to the owner as option (b) of
the new action, not adopted here.

## 6. `OA-pin-path-corpus`: re-measured where it touches this change

Left open, as instructed. Its two widenings are neither obsolete nor merely
stale; each needs a different answer.

* The ever-tracked widening added twenty-six rows when it was measured, of which
  twenty-four were the vendored catalog's `rust_bindings` and two were this
  pin and its reconciliation mirror. Those two have LEFT the widening: the path
  is now in `git ls-files`, so it is inside the base corpus rather than added by
  it, and it is not a candidate there because its declared digest is the file's
  current digest. Measured after the change: the path is absent from the
  ever-tracked-but-not-now set, and all four of the source paths behind the
  other rows are still in it. So that widening now lands twenty-four rows on the
  declared basis, not twenty-six.
* Neither widening's TOTAL survives, and not because of this change. Both were
  measured over a corpus of 1997 JSON artifacts and an ever-tracked set of 2388
  paths. This tree carries 3501 tracked JSON artifacts today and an ever-tracked
  set of 5321 paths, of which 856 are no longer tracked. The totals need a full
  re-derivation before either is quoted again.
* `.quarantine` is still in the ever-tracked set, so the F011 re-admission
  hazard the action names is exactly as it was.

The pin-guard ceiling carried the sentence that this pin's target was "deleted
from this plane" and that the census "has never counted it". This change made
that false, so the ceiling was rewritten in the same commit; the test that
requires the disclosure to keep naming the path and the untracked-path rule
still passes.

## 7. Gates

Run from a committed tree, with `VJWP_PROTECTED_STORE` set to
`evidence/governance/decisions` and the quarantined JDK first on PATH. The exit
code and the full census are in section 8.

## 8. What could not be resolved

* The second clause of the ruling, for all five pins. It is an owner question
  now, with the measurement attached.
* Whether pins 1, 3 and 4 should be satisfied by reverting this line's files to
  the Codex bytes, re-pinned to this line's current bytes, or left as declared
  findings. All three are basis moves of different sizes and the ruling's text
  fits the smallest of them least well.
* `docs/us023-formal-coverage.md` carried an on-disk digest for
  `assurance/formal/proof-targets.json` of `sha256:bad1e069…`. The file is
  `sha256:0f514b0c…` today and was before this change, so that value had already
  rotted. Section 3.1 of that page had to change anyway, so it now points at the
  derived reconciliation instead of restating a frozen digest. The rot was not
  mine and is disclosed here rather than quietly re-frozen.
* `corpora/frame/codec.json` cites `../../schemas/frame-codec-corpus-1.0.0.schema.json`,
  which exists at `1ff89fa` and not here. Nothing in this tree resolves that
  reference, so no gate reads it, and the schema is not one of the artifacts the
  basis pins. It was left alone rather than copied in on my own initiative.
* Whether `assurance/developer-tools/port-seam-dossier.json`, a 705-byte
  placeholder with one seam, is the document the catalog's denominator was
  really derived from. It agrees with its pin only because it has not diverged
  since the fork.
