# Landing record — claude/ledger-integrity → mainline (goal-loop, interactive after iteration 2)

Recorded 2026-09-02T09:34:52Z by the goal loop from tool output. Landing check, not an
independent review; the branch's substantive review is its own four rounds.

## What landed

- Branch head before the forward merge: aa422e2 (review PASS at round 4, per
  the merge-queue table in `.claude/HANDOFF.md`, written 2026-08-29).
- Forward merge of mainline 09bed38 into the branch: f052795, clean; the
  `git merge-tree` dry run gave tree 122bd90, equal to the merged tree.
- Mainline merge commit: 2fbad99. Mainline tree 122bd90 equals the branch tree.
- 37 files: `internal/deltaledger` (integrity, census, observations,
  supersessions, governance digest mirror), `internal/corpora/{derive,store}.go`,
  `internal/lab/{evidence,supersession}.go`, six schemas, the evidence
  documents they bind, and `rust/Makefile`, which adds `ledger-gates`
  (`deltaledgerctl --root . --check`) to the `gates` chain. No Rust source
  changed: `git diff --quiet <mainline> HEAD -- rust ':!rust/Makefile'` exits 0.

## Validation on the merged tree, exit codes read directly

- `make -C rust gates` with `VJWP_PROTECTED_STORE` exported: ac1-gates
  PASS 8/8, then `ledger-gates` ok — ledger equals its regeneration (48
  records, head sha256:ab9277cb…), 3 supersession links, integrity verified
  with unledgered_disagreements recomputed = 0, and 4 governance record
  digests recomputed from the protected store and matched. `gates exit=0`.
- `internal/corpora` changed, so the differential and exam were re-run on the
  merged tree: public request digest 0c1503c0… and handshake request digest
  e00d968f… unchanged; harness 414d7e5b… unchanged; port 74/74 and 49/49
  (runtime neutralised); live Java 74/74 and 49/49 with 16 divergences. No
  corpus shift.
- `go build ./...` exit 0. `go test -count=1 ./...` with
  `VJWP_PROTECTED_STORE` exported: 29 packages ok, including
  `internal/deltaledger`, `internal/corpora`, `internal/formalplan`. Two
  packages fail for environment reasons: `internal/lab`
  PLATFORM_EXECUTOR_UNSUPPORTED (Darwin sandbox-exec), and `internal/portplan`
  JAVAC_UNAVAILABLE — the derive step requires the pinned JDK 17.0.19 and this
  image has javac 21.0.10. Without the store exported, twelve
  `internal/deltaledger` tests fail with THE PROTECTED GOVERNANCE STORE IS NOT
  REACHABLE; that is the gate's designed refusal, not a defect.

## Environment change made during this landing

- The pinned upstream source archive was reproduced byte-exactly from an
  anonymous shallow clone of TooTallNate/Java-WebSocket: `git archive
  --format=tar --prefix=Java-WebSocket-<commit>/ <commit> | gzip -n -6` yields
  sha256 f44e7647… and 190008 bytes, equal to the intake pin; placed at
  `.quarantine/java-websocket-source-archive.tar.gz`, which the code digest-
  verifies before extracting. `internal/formalplan` passes here as a result.

## Findings

- None blocking.
- Observation: the merge-queue table and "Where things stand" in
  `.claude/HANDOFF.md` are now two branches stale; `.claude/GOAL-LOOP.md` is
  the live record.
