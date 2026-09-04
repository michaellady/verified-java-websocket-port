# The Go suite as a gate, with its exclusions declared

## Why

`make -C rust gates` exited 0 for the whole of 2026-09-03 while
`internal/deltaledger` was failing three subtests, **two of them the governance
gate accepting a document it exists to refuse**. The chain does not run the Go
packages. I read "gates green" as "the tree is good" repeatedly, and landed on
that reading in commit messages.

It was found by an agent that ran `go test ./...` on clean mainline rather than
trusting the chain. That should not have been necessary.

## What this is

`cmd/gosuitectl`, wired into `gates` as `go-suite`, ahead of `test`.

It runs everything `go list ./...` reports **except** a named list with a reason
per entry:

| package | why it cannot pass here |
| --- | --- |
| `internal/lab` | `CONTROLLED_CANARY` requires Darwin `sandbox-exec`; `PLATFORM_EXECUTOR_UNSUPPORTED` on Linux. Owner gate: a macOS host. |
| `internal/portplan` | `TestDeriveReproducesCommittedEvidence` byte-compares the regenerated semantic-id oracle against the committed one, which records `jdk_vendor "Homebrew"`; a Linux Temurin regeneration differs in that ONE line, all 969 declarations identical. Owner decision: vendor-agnostic check, or pin the vendor. |

## The three properties that make it a gate rather than a list

1. **The run set is the COMPLEMENT of the exclusions.** A package added tomorrow
   is covered without anyone remembering to add it. A list of packages to run
   would have exactly the hole this exists to close.

2. **A stale exclusion FAILS.** An exclusion naming a package that no longer
   exists is a lie about coverage — the gate reports "excluded by name with a
   reason" for something it could simply have run. `STALE_EXCLUSION`, exit 1.

3. **An exclusion must say what would lift it.** An 80-byte floor on the reason
   and a required mention of the owner action. This is the effort floor the
   legacy-adjudication gate already puts on its arguments: it cannot judge
   quality, but it can refuse an empty reason. It stops the list becoming
   somewhere to park a failure.

## The precondition, refused rather than worked around

`.quarantine/` is gitignored, so it exists only in the checkout that populated
it, and a fresh `git worktree` has none. Without it `internal/formalplan` and
`internal/portplan` fail citing the archive as `HTTP 403` — which reads exactly
like the proxy refusal and is not it. **Two agents reported that as a third
environmental failure** before anyone noticed the tree was simply never staged.

So the gate refuses, exit 2, naming the fix:

```
gate=go-suite result=REFUSED
  reason=".quarantine/ is not staged in this tree, so the packages that consume
   the pinned Java source cannot be told apart from ones that are genuinely
   broken. This is a refusal, not a failure, and not a skip."
  remedy="ln -s /home/user/verified-java-websocket-port/.quarantine <root>/.quarantine"
```

Same shape as `ledger-gates` refusing without `VJWP_PROTECTED_STORE`, and for
the same reason: an unstaged tree cannot tell a blocked package from a broken
one, and guessing is how a wrong baseline gets published.

## What this does NOT do

- It does not make the two excluded packages pass. Both owner actions stand.
- It does not shorten the chain. `gates` now takes several minutes longer,
  because `internal/formalplan` alone runs 390-409s. That is the price of the
  chain meaning what it is read to mean, and it is worth paying: the alternative
  is what happened on 2026-09-03.
- It does not check the Rust side, which `test` and `test-release` already do.

## Readings

- Refusal path exercised against a directory with no `.quarantine`: exit 2 with
  the remedy naming that directory. Read from the process.
- `go test ./cmd/gosuitectl/` exit 0, 4 tests.
- The exclusion list is validated against the real module by
  `TestEveryDeclaredExclusionNamesAPackageThatExists`, so it is checked on every
  run rather than only when someone looks.

## The exclusion list, checked against a full run rather than assumed

`go test -count=1 ./... -timeout 60m` on `f62dcc7`, with `.quarantine/` staged
and the pinned JDK on `PATH`:

```
ok   = 43
FAIL = internal/lab       6.654s
FAIL = internal/portplan 18.003s
EXIT = 1
```

**Exactly the two packages this gate excludes — no more, and no fewer.** That is
the check that matters: an exclusion list justified only by the reasons written
beside it would be an assertion, and this is a measurement of the same set from
the other direction. Had the run shown a third failure, the list would be short
and the gate would be lying about its coverage; had it shown one, an exclusion
would be stale and `STALE_EXCLUSION` would already have failed the gate.

It also settles the baseline claim in `.claude/GOAL-LOOP.md` step 4 for this
head: two environmental failures, both named, both with an owner action, and
41 of the 43 remaining packages carrying real checks that now run inside
`gates` instead of beside it.
