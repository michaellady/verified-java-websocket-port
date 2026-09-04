# Landing record — claude/us008-restart → mainline (goal-loop iteration 2)

Recorded 2026-09-02T08:30:28Z by the goal loop from tool output. This is a landing check, not
an independent review; the branch's substantive review is its own five rounds.

## What landed

- Branch head before the forward merge: 10a1dc1 (review PASS at round 5, per
  the merge-queue table in `.claude/HANDOFF.md`, written 2026-08-29).
- Forward merge of mainline 90d73d2 into the branch: 9096f07, clean. The
  `git merge-tree` dry run produced tree 8d4801a, equal to the merged tree.
- Mainline merge commit: e7a66a0. Mainline tree 8d4801a equals the branch tree,
  so the landing added nothing beyond the branch's own diff.
- Nine files: `benchmarks/environments/confirmation.json`,
  `docs/us008-attestation-package.md`, `internal/benchplan/{decide,drift,validate}.go`
  and their tests, `schemas/benchmark-raw-sample-1.0.0.schema.json`.
  `git diff --quiet <mainline> HEAD -- rust` exits 0: no Rust change.

## Validation on the merged tree, exit codes read directly

- `make -C rust gates` with `VJWP_PROTECTED_STORE` exported:
  `ac1-gates verdict=PASS gates_passed=8/8`, exit 0.
- `go build ./...` exit 0. `go test -count=1 ./...` exit 1 with 28 packages
  ok, `internal/benchplan` among them (130.7 s). Failures confined to the
  three environment-only packages with the same typed findings as the
  iteration-1 baseline on unmerged mainline: `internal/lab`
  PLATFORM_EXECUTOR_UNSUPPORTED (1); `internal/formalplan` and
  `internal/portplan` JAVA_SOURCE_UNAVAILABLE_OFFLINE (17),
  JAVA_QUARANTINE_UNAVAILABLE (5), ORACLE_TREE_MISMATCH (1). See
  `.claude/CLOUD-ENVIRONMENT.md`, "Known environment failures".
- Corpus differential and handshake exam: not re-run. No behaviour-bearing
  path changed (`rust/` and `java-oracle/` untouched).

## Findings

- None blocking.
- Observation: the PRD `passes` flag for US-008 cannot be updated here because
  the PRD is not in the repository. US-008's confirmation-host run remains an
  owner gate regardless.
