# F015 — two pull requests to `main` from histories with no common ancestor

## What I was doing

Checking a standing requirement: that the branch being pushed has an open pull
request. It did not, which is the small half of what I found.

## The state

`gh`-equivalent listing of open PRs:

| PR | head | base | draft |
| ---: | --- | --- | :---: |
| #4 | `claude/us019-native-run` | `claude/feature/verified-java-websocket-port` | yes |
| #1 | `feature/verified-java-websocket-port` | `main` | yes |

`main` is `45f0fa3 Initial commit`. **Nothing has ever merged to it.**

`claude/feature/verified-java-websocket-port` — the branch every loop iteration
has landed on — had no pull request at all. Opened as #5.

## The finding

`feature/verified-java-websocket-port`, the head of PR #1, and
`claude/feature/verified-java-websocket-port`, the current line, share **no
common ancestor**:

```
git merge-base origin/feature/verified-java-websocket-port \
               origin/claude/feature/verified-java-websocket-port
(empty)
```

Two unrelated histories, both targeting `main`. Mine is 465 commits ahead of
`main` with 2930 files; PR #1's is 44 ahead with 213, all of it US-007
Docker-sandbox work (`protected Docker sbx adapter`, `sandbox-scoped deny-all`,
`sbx clone control plane`, `supervisor bound to retained policy`, `keep sbx
authority external`).

An entire story sitting on a history the mainline cannot reach is exactly the
shape of stranded work, and the board separately lists "child US-009 AC1 Docker
sbx replay" as an outstanding owner gate. So the question is not academic.

## It is superseded, not stranded — checked rather than assumed

All 8 sbx-related paths on PR #1's branch exist on mainline. Five differ, one is
byte-identical, none are absent.

On the substantive one, `internal/securitygate/sbx_adapter.go`:

- PR #1's branch: 31992 bytes, 14 exported symbols.
- Mainline: 54466 bytes, 25 exported symbols.
- Exported symbols PR #1's version declares that mainline lacks: **none**
  (`comm -23` over both symbol sets is empty).

So mainline's public surface is a strict superset on that file, and nothing would
be lost by abandoning that line. I checked the symbol sets rather than reading the
byte counts as evidence — a larger file is not proof of a superset, which is the
existence-standing-in-for-identity error this project is named for.

## What this does NOT establish

- That mainline's sbx work is *better*, only that it is a superset on that one
  file's exported surface. I did not diff behaviour, and I did not check the other
  five differing files symbol by symbol.
- That US-007 is complete. Its Docker sbx replay is still an owner gate.
- What should happen to PR #1. Closing someone's pull request is not mine to do;
  it is recorded here so the decision can be made with the ancestry known.

## Why it matters beyond housekeeping

A reviewer arriving at this repository sees two draft PRs into an empty `main` and
no indication that one supersedes the other. The 44-commit one is smaller and
older and looks like the tidier candidate. Nothing in either PR said which line is
live until #5 was opened and said so.

## Status

Recorded. PR #5 opened for the live line, with the ancestry, the gate state, the
measured ceilings and the six blocking owner decisions in its body. PR #1's
disposition is an owner action, named and not taken.
