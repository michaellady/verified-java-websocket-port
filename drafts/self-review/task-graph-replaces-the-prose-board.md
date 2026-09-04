# The plan as data, with a gate that re-derives it

## Why the prose board had to go

The loop read `.claude/GOAL-LOOP.md` and picked "ONE bounded unit of work from the
top of the priority queue whose preconditions hold". Three failures, all observed
over 2026-09-03/04:

- **The one-unit rule was ignored every firing.** I did five or six units per
  firing and never once stopped at one. A rule nothing enforces is a rule nobody
  follows, including its author.
- **Priorities were re-derived from prose each time**, at real cost, and
  inconsistently — the same firing could reach a different ordering.
- **Blocked-versus-ready lived only in whoever was reading.** Which of the
  outstanding items were waiting on the owner, and which were merely unstarted,
  was never written down in a form anything could check.

And prose rots. `drafts/self-review/normalization-collision-audit.md` stated *26
distinct scored observations* while `evidence/normalization-collisions/audit.json`
measured **29**, for hours, because nothing read the prose. That is the same file
class the board is.

## What replaced it

`assurance/plan/task-graph.json` — 28 nodes, 13 owner actions — and
`cmd/taskgraphctl`, wired into `gates` as `plan-guard`.

Five rules, recomputed on every run:

1. Every `depends_on` names a real node; every `blocked_by` names a real owner
   action. A dangling reference is a plan about nothing.
2. No cycles.
3. **Readiness is recomputed, never read.** A node cannot be `ready` while a
   dependency is unfinished or an owner action it names is still open.
4. **A node cannot stay `blocked` once every owner action it names is ruled.**
   This is the state the plan is most likely to get wrong, because a ruling
   arrives from OUTSIDE the file and nothing here would otherwise notice. Four of
   thirteen owner actions were ruled at once on 2026-09-04; without this rule the
   plan would have gone on calling their nodes blocked indefinitely.
5. **A `done` node must cite evidence this gate RE-DERIVES, and it must still
   hold.** Not "name evidence" — name evidence of a kind the program checks.

Rule 5 is the load-bearing one, and the reason `command` evidence does not count
toward it. A command is recorded so a reader can run it; it is never treated as
verified. A node declared done on a command nobody runs is `UNVERIFIABLE_DONE`
and fails — because that is precisely the shape of every gate defeated here on
2026-09-04: a well-formed declaration whose claim went unchecked.

Evidence kinds the gate re-derives: `path_exists`, `path_absent`, `grep`,
`grep_absent`, `git_tracked`, `git_not_tracked`.

The git kinds exist because several fixes in this repository are claims about what
git TRACKS — F011's self-referential `.quarantine` symlink, the 3.9 MiB binary I
committed. Citing the finding that records such a fix would prove only that the
finding exists, which is this project's founding defect class.

## It caught a live regression on its first run

The first execution against the real tree failed with five findings. One was real:

```
finding=EVIDENCE_NO_LONGER_HOLDS node=T-F011-quarantine
  detail="git_not_tracked .quarantine: git tracks it and must not"
```

**F011 had regressed.** `.quarantine` was tracked again in mainline at blob
`449d870f` — the SAME self-referential blob — re-added by `f26e062`, an agent's
`git add -A` stub commit. Two separate agents disclosed making this mistake and
both said the root fix was "not mine to make here".

The root cause is that `.gitignore` line 30 reads `.quarantine/`, the DIRECTORY
form, which does not match a symlink. Agents isolate by symlinking `.quarantine`
into their worktree and `git add -A` stages the link. Fixed by adding the bare
path `.quarantine` beside it, with the reason written where the next person will
read it. Verified: `git check-ignore -v` now resolves the symlink form to the new
line.

The other four findings were **my own bug in the evidence patterns**: Go's
`regexp` anchors `^` to start-of-text, not start-of-line, without `(?m)`. So
`^gates:.*record-guard` never matched a Makefile whose first line is a comment.
Four "done" nodes were reported as having lost their evidence when the evidence
was fine and my regex was wrong. Fixed with `(?m)`; worth recording because a
gate that cries wolf gets ignored, which is worse than one that stays quiet.

## Polarity, read from the process

```
A blocked node whose owner actions were all ruled:
  finding=STALE_BLOCK node=T-us019-ac4 "every owner action it names is RULED and
    every dependency is done, so this is ready and the plan has not noticed"
  result=FAIL, exit 1

A done node whose cited evidence stops holding:
  finding=EVIDENCE_NO_LONGER_HOLDS node=T-pin-guard "grep …: pattern … no longer matches"
  result=FAIL, exit 1
```

`task-graph.json` restored byte-identically after each, `diff -q` clean.

Ten tests cover each rule firing and, for the two that matter most, the opposite
direction as well: one checkable evidence item that HOLDS is enough to pass, and
one OPEN owner action is enough to stay legitimately blocked.

## Current reading

```
nodes=28 done=11 ready=5 in_progress=3 blocked=9 owner_actions=13 open=9
```

Nine of thirteen owner actions are open, and nine nodes are blocked on them. Four
were ruled on 2026-09-04 and their three nodes are in progress.

## What this does NOT do

- It checks the plan's INTERNAL consistency and that each done node's cited
  evidence still holds. It does **not** check that the evidence is SUFFICIENT for
  the claim. A node may cite a weak-but-true fact and pass.
- It does not discover work. A task nobody wrote down is invisible, so the graph
  is a **floor** on what remains, never a total.
- It does not replace the heartbeat. Something still has to wake this session, or
  the plan simply sits there. The trigger and the plan are orthogonal, and only
  the plan changed.
