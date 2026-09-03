# F008 — two failing packages were explained by the nearest available story, and the story was wrong

phase: catalog plane correspondence / US-023 formal coverage   step: item 3   date: 2026-09-03T00:40Z

**what happened:** the task that produced this branch stated, as established fact, that
`cmd/formalcoverctl` and `internal/formalcoverage` fail "because they cite
`corpora/frame/codec.json`, absent here for plane reasons," and noted that this had "been
miscounted as environment baseline all session." That framing came from F006, which had
just established — correctly — that `corpora/frame/codec.json` exists on the Codex plane
and nowhere else. **The failures have nothing to do with it.** Regenerating the retained
artifacts and reading the diff shows exactly one changed field: the pinned identity of
`evidence/linkage/rust-identity-verification.json`, `7b23139` → `4eb417b`. The report was
retained at `bce5a07`; mainline had already moved that file at `518c81a` (the DIV-06
handshake change shifted `rust/ws-core/src/connection.rs`, so the linkage overlay was
refrozen); the merge `92556bd` took mainline's newer file and nothing regenerated the
report. Ordinary stale derived evidence after a merge, on this plane, with no plane
question in it at all.

**how the wrong story survived:** `corpora/frame/codec.json` IS absent, and it IS named in
the reconciliation, and the reconciliation IS an input to the failing report. Every clause
is true. The conclusion does not follow, and the disproof was one command away: the
reconciliation test — the one that reads that pin — **passed throughout**. An absent basis
pin had already been reconciled into the retained bytes and could not fail a byte
comparison against those same bytes. Nobody ran the comparison and read the diff; the
nearest true-sounding fact was promoted to the cause.

**bin:** the same root as F001 and F006 — running a check, or accepting one, without
pinning what it is a check ON — but a third face of it. F006 named *existence standing in
for identity* and its mirror *absence standing in for defect*. This is **the most recent
explanation standing in for the diagnosis**: a fresh, vivid, correct finding about
something nearby, reached for as the cause of an unrelated failure. It is more dangerous
than a guess because it arrives with evidence attached — just evidence for a different
claim.

**cost:** small here, because the fix (regenerate the retained artifacts) is the same
either way. The cost was almost paid elsewhere: had I acted on the brief, I would have
looked for a plane-shaped repair to a merge-shaped staleness, and the real cause — that
nothing regenerates a derived report when a merge brings a newer input — would have stayed
invisible for a third session.

**the portable rule:** a failing test's cause is what the process prints, not what the
last interesting finding suggests. Before adopting an explanation, run the failure and
read its output. If the explanation names an artifact, check whether the test that reads
that artifact is among the failures — here it was not, and that alone refuted the story.

**what is still open:** nothing in the tooling notices that a retained derived artifact has
gone stale until someone runs `formalcoverctl verify`. That command is not in `make -C rust
gates`, and the two Go test packages that do notice were being counted as baseline noise.
Whether the verify step should join a gate is an owner call, not a change to make quietly.

evidence: `go run ./cmd/formalcoverctl report -repo .` then `git diff` (one field, one
file); `git log --follow` on `evidence/linkage/rust-identity-verification.json` showing
`518c81a`; `git rev-parse bce5a07:<path>` = `7b23139` against `HEAD:<path>` = `4eb417b`;
`TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive` passing in the same run in
which `TestRetainedReportsAreExactlyWhatTheEvidenceDerives` failed.
