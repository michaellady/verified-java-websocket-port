# A plan that could be emptied of its obligations

The round-2 adversarial review reported, as a hard stop it did not fix, that
nothing counts plan nodes: deleting nine blocked nodes gave `nodes=20 ... open=1`
at exit 0. This is the follow-on. I measured the hole before building anything
against it, and it was worse than reported.

## What was measured

Against the merged plan (31 nodes, 15 owner actions), deleting whole classes of
node and pruning the dependency edges that would have dangled:

| deletion | census after | exit | gate said |
| --- | --- | --- | --- |
| every `blocked` node (11) | `nodes=20 ... blocked=0` | 0 | PASS |
| every `ready` node (3) | `nodes=28 ... ready=0` | 0 | PASS |
| every `done` node (15) | `nodes=16 done=0` | 0 | PASS |

The third row is the one that matters. With every done node deleted the gate
still printed `result=PASS detail="every done node's evidence re-derived"` --
vacuously true of an empty set, and indistinguishable in a log from the same
sentence about fifteen nodes. Every other rule in plan-guard is satisfied by
whichever nodes survive, so a plan can be emptied of its obligations one commit
at a time and each commit passes.

## Why there was no source to check against

Every other gate in this repository re-derives its claim from something in the
tree. This one has nothing to re-derive from: the plan **is** the record of
intent, and intent has no independent existence elsewhere. That is why the hole
was left open in round 2, and the reasoning was sound as far as it went.

But the plan has a **history**. Every version this repository ever committed is
a prior statement, by the people who wrote it, of what was outstanding at that
moment -- and git is a store that a program can read without trusting the working
copy. So the rule is not "count the nodes" (there is no number to count against)
but "an id this plan once committed may not simply vanish".

## Rule 12

`cmd/taskgraphctl/history.go` walks every commit touching
`assurance/plan/task-graph.json`, unions the node ids and owner-action ids each
version declared, and refuses any id that is absent now:

```
gate=task-graph finding=NODE_DISAPPEARED node=T-pin-guard detail="declared by this
plan as recently as 8dbef0987b1f and absent now, with no `retired` entry explaining it"
```

Re-running the three deletions above now gives 11, 3 and 15 findings at exit 1,
one per deleted node, each naming the commit that last declared it. The
unmodified plan gives zero findings at exit 0. It walks the **full** history
deliberately: capping the walk would let a deletion age out of view.

Disappearance is not always wrong -- nodes get renamed, two get merged -- so
there is an escape, in the declared-exemption shape this repository already uses
four times (`STALE_EXCLUSION`, `STALE_COVERAGE_CLAIM`, `STALE_ALLOWANCE`,
`STALE_BLOCK`). A `retired` entry may explain one id, and the entry is itself
re-derived on every run:

| finding | when |
| --- | --- |
| `STALE_RETIREMENT` | the id is still in the plan; the exemption outlived what it excused |
| `FICTIONAL_RETIREMENT` | no committed version ever declared that id |
| `RETIREMENT_WITHOUT_REASON` | a removal nobody explained is a removal nobody reviewed |
| `DANGLING_SUCCESSOR` | `superseded_by` names an id the plan does not declare |
| `RETIREMENT_UNKNOWN_KIND` | and the disappearance is still reported, not excused |

## The first implementation was fail-open, and its own test caught it

This is the part worth recording. An unreadable history is a refusal rather than
a skip -- the rule the governance mirror already states for an unreachable
protected store -- so I added a completeness precondition: the oldest readable
commit touching the plan must be the commit that **added** it. If it is not,
older versions sit beyond the clone's boundary and "no committed version ever
declared that id" would be a guess.

It did not work. `TestTruncatedHistoryIsRefused` builds a real repository whose
plan drops a node, clones it at `--depth 1`, and expects a refusal. It got
`map[]` -- no findings at all.

The reason: **git presents a shallow graft point as a root commit.** With no
parent in the clone there is nothing to diff against, so every file the boundary
commit contains looks freshly ADDED. `--diff-filter=A` therefore reported the
plan as originating at the boundary, the precondition passed, and a depth-1
clone that was hiding a deletion reported the plan intact. The check I added to
close a fail-open hole was itself fail-open.

`historyComplete` now consults the graft points directly, from git's own
`shallow` file, and refuses when the plan's oldest commit is one of them.

This is not hypothetical. **This checkout is shallow** -- `git rev-parse
--is-shallow-repository` reports true, with four graft points -- and
`actions/checkout@v4` defaults to `fetch-depth: 1`. The repository passes only
because its graft points sit below `8218815`, the commit that added the plan, so
every version of the plan is present. A CI job running this gate on a default
checkout would get `PLAN_HISTORY_TRUNCATED` and the remedy in the message, which
is the correct outcome and not a silently weaker check.

## What this does not establish

- **A `reason` is prose no program can verify.** Retiring a node with a plausible
  sentence gets past rule 12. The staleness, fiction, successor and kind checks
  stop the escape becoming a standing allowlist, but they cannot judge whether a
  removal was honest. The gate makes the removal **visible in the diff**; a
  reviewer decides.
- **A rewritten history erases the evidence along with the node.** An amend or a
  force-push that removes the versions declaring an id removes this rule's source
  too.
- **A node added and removed without ever being committed leaves no trace.**
- **During an uncommitted merge the incoming branch is not yet in HEAD's
  ancestry**, so a node dropped while resolving a merge is caught on the next run
  rather than that one.
- The rule binds ids, not content: a node can be gutted -- title, note and
  evidence replaced -- and rule 12 is silent, because the id is still there. The
  sufficiency gap the ceiling already measures is unchanged by this work.

All five are now in `CeilingText`, which the plan mirrors and cannot author.

## Two findings carried in from verifying the round-2 branch

I re-ran seven of the fifteen plan-guard bypasses independently against the
merged gate rather than reading the report: the empty plan, `path_exists` with
`""` and with `"."`, an empty `grep` pattern, `grep_absent "^gates:"` without
`(?m)`, `git_not_tracked ""`, and a path outside the tree. All seven refused;
the unmodified plan passed. The fixes hold.

**The governance mirror's claim was an overclaim, and it is now corrected.**
`rust/Makefile` said "Deleting or editing a governance record fails this target."
Measured: the mirror covers 7 records, the store holds 63, and deleting
`us007-attempt-0101-owner-authorization.json` leaves `deltaledgerctl --check` at
exit 0 -- still printing "7 governance record digest(s) recomputed from the
protected store and matched", which is true, and true of 7. The comment now names
the 7 and states the measurement. Whether to widen the mirror is
`OA-governance-mirror-coverage`: the 7 are DERIVED from the ledger's own digest
citations rather than chosen, so widening replaces a derivation with an
enumeration, moves a declared count, and re-opens a disclosure question the owner
settled in `governance-publish-records-owner-decision-2026-08-29.json`.

**A governance record's prose asserts the opposite of the tree it sits in.**
`evidence/governance/owner-decision-digests.json` `$.statement` still says the
records are "deliberately NOT committed: this repository is public and those
records carry internal deliberation, cost figures and infrastructure
identifiers". All 64 files in `evidence/governance/decisions/` are git-tracked,
and the sha256 of all 7 mirrored records recompute against those tracked files,
so the tracked tree **is** the store the statement says is uncommitted. This is
not a disclosure incident: the README beside it records that the assessment "was
measured afterwards and found to be overstated" and that the owner directed
publication with redactions. It is stale prose in the one part of that file
nothing checks -- `VerifyGovernance` verifies its digests, never its statement.

Alongside it, the store's README says "The 62 JSON files beside this README" and
"Across all 62 records there are no credentials of any kind". The store held
**63** at `b6d3c6c`, the commit that wrote that README, and holds 63 now; the
count was wrong on the day it was written. I re-derived the security claim over
all 63 rather than trusting either number, and **it holds**: 0 ARNs, 0
AKIA/ASIA keys, 0 private-key headers, 0 s3 references, 0 non-loopback IPv4. The
three `i-[0-9a-f]{8,17}` hits are the tail of `ami-02b3d83d84b07786d`, the public
AMI the README explicitly declines to redact; the five 12-digit hits are digit
runs inside sha256 digests. Both redaction placeholders are present where the
README's table says. So: a true assertion over a mis-stated denominator.

Both belong to `T-other-record-prose` and have been handed to that work rather
than fixed here, because this project corrects records by supersession and that
mechanism is what that node is building.

## A third finding, met by walking into it

Running gates on the round-2 merge gave `GATES_EXIT=2`, with `internal/portplan`
red on two tests:

```
Derive: JAVAC_UNAVAILABLE: javac reports "Picked up JAVA_TOOL_OPTIONS: ...
\njavac 21.0.10", pinned JDK is 17.0.19
```

It reads as a broken pin. It is not. The pinned JDK lives at
`.quarantine/jdk-17.0.19+10`, the container's default `javac` is 21.0.10, and my
gates invocation exported `VJWP_PROTECTED_STORE` but not the PATH. Measured both
ways on unmodified code: off PATH it fails in 0.2s, on PATH the same two tests
pass in 6.9s.

Before concluding that, I checked the cheaper explanations rather than assuming
the environment: `internal/portplan` is byte-identical between the merge and its
base (`git diff 6986e95 --stat -- internal/portplan` is empty, so the merge
cannot have caused it), and the JDK 21 packages date from 2026-03-31 in
`/var/log/dpkg.log`, so nothing in this session installed them.

`cmd/gosuitectl/main.go:117` already described this exact shape -- portplan
"failed JAVAC_UNAVAILABLE instead whenever the pinned JDK was off PATH, which is
a different problem wearing the exclusion's name". **Recording it was not
enough.** The comment sat eighty lines from the failure, and the failure arrives
as a red package at the bottom of a 250-line log.

The asymmetry is the finding: `ledger-gates` REFUSES by name when
`VJWP_PROTECTED_STORE` is unset, and `go-suite` itself REFUSES by name when
`.quarantine/` is not staged -- both on the stated principle that an
unreachable input is a refusal rather than a failure, because a gate that cannot
tell a blocked package from a broken one should say so. The pinned JDK is the
same kind of input and had no such refusal. It does now:

```
gate=go-suite result=REFUSED reason="the pinned JDK is not on PATH, so
internal/portplan cannot be told apart from a genuinely broken package: javac on
PATH is \"javac 21.0.10\", and internal/portplan pins 17.0.19. This is a refusal,
not a failure, and not a skip." remedy="export
PATH=/home/user/verified-java-websocket-port/.quarantine/jdk-17.0.19+10/bin:$PATH"
```

The version is extracted rather than quoted whole, and that is tested: the agent
proxy sets `JAVA_TOOL_OPTIONS`, so javac prints a banner carrying a proxy port, a
truststore path and a forty-entry `nonProxyHosts` list before the version, and
quoting the blob is how "javac 21.0.10" got lost in the first place.

This is outside the node's scope and I am saying so rather than folding it in
quietly. I took it because the diagnosis was already paid for and the next person
would have paid it again. What I did **not** do -- and told the three agents
running in parallel not to do, before they hit the same red package -- is change
`PinnedJavacVersion`, relax the version check, or re-add `internal/portplan` to
the exclusion list. Each would turn a real check off to make a log green.

## Gates

`make -C rust gates` on this branch: see the commit message for the exit code and
census, transcribed from the run. Both preconditions were exported for it.
