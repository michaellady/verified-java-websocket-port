# F012 — four agents in one working tree, and a merge parent that vanished

## What happened

I launched five parallel agents. Four of them created their branches with
`git checkout -b` in the **shared main working directory**
(`/home/user/verified-java-websocket-port`) rather than taking a worktree. The
fifth made its own worktree at `/home/user/vjwp-survivor` and was never
involved in any of this.

The reflog, read afterwards, is the whole story:

```
425878e HEAD@{0}: checkout: moving from claude/f010-banner-adjudication to claude/normalization-collision-closure
425878e HEAD@{1}: commit: Merge claude/us022-mutation-denominator: …
94edcbc HEAD@{2}: checkout: moving from claude/ledger-adjudication-round to claude/f010-banner-adjudication
94edcbc HEAD@{3}: checkout: moving from claude/quarantine-baseline-recovery to claude/ledger-adjudication-round
94edcbc HEAD@{4}: checkout: moving from claude/feature/verified-java-websocket-port to claude/quarantine-baseline-recovery
94edcbc HEAD@{5}: commit: Fix two mainline defects three agents inherited: …
```

Four checkouts in a few minutes, all in one tree. My own US-022 landing sits at
`HEAD@{1}`, between the third and fourth of them.

## The damage

Two distinct injuries, and the second is the one I nearly missed.

**The visible one.** `git commit` recorded onto whichever branch label HEAD
happened to be carrying. My mainline merge landed on
`claude/f010-banner-adjudication`, and mainline
(`claude/feature/verified-java-websocket-port`) stayed behind at `94edcbc`. I
caught this only because `git push` answered `Everything up-to-date` when I knew
I had just committed. Had the push reported success I would not have looked.

**The one that hid behind it.** I ran `git merge --no-ff --no-commit`, verified
the merged tree, then committed. `git log -1 --format=%P` on the result shows
**one parent**. A `git checkout` clears `MERGE_HEAD`, so by the time I committed
there was no merge in progress — the staged tree got committed as an ordinary
commit. Git recorded the CONTENT of the merge and none of its ANCESTRY. Nothing
failed. No warning. `git status` between the two would have said so, and I did
not run it.

## What was NOT damaged, checked rather than hoped

- `git ls-tree -r 425878e | grep -c 'mutdenom|assurance/mutation'` → **92**.
- `git diff 425878e 418452c -- internal/mutdenom cmd/mutdenomctl assurance/mutation`
  → **empty**. The US-022 content is byte-identical to its branch.
- `make -C rust gates` exit 0 had run on exactly that content.

The checkouts were all between branch labels pointing at the *same* commit, so
they were content no-ops. That is luck, not design. Had any of those four agents
been on a branch with different content, the checkout would have either failed
on the staged files or silently swapped the tree under my verification, and my
"gates exit 0" would have been a reading of something other than what I
committed. That is the same shape as the straddled background run one of these
very agents caught itself doing earlier today and correctly discarded — a check
whose subject was not pinned. Mine was worse, because I published the result.

## The repairs

Mainline ref, without checking anything out (mainline was checked out nowhere):

```
git branch -f claude/feature/verified-java-websocket-port 425878e
git push origin 425878e:refs/heads/claude/feature/verified-java-websocket-port
```

Ancestry, as a content-free merge that exists only to record the second parent:

```
git merge -s ours --no-ff 418452c        →  87f754b
git diff --stat HEAD^ HEAD               →  empty
git log -1 --format=%P                   →  425878e 418452c
git branch --contains 418452c            →  claude/feature/verified-java-websocket-port
```

I did not rewrite `425878e`; it was already pushed, and rewriting published
history to tidy a DAG is a worse trade than carrying one explicit repair commit
that says what it is.

And a dedicated worktree for my own mainline work, `/home/user/vjwp-main`, so I
am no longer sharing a tree with anything: `git worktree add /home/user/vjwp-main
claude/feature/verified-java-websocket-port`.

All four agents were told to isolate before doing anything else, with the exact
`git worktree add` command and their new branch name. All four confirmed
isolation. One of them volunteered that it had left the main tree clean with
zero modified files, which is exactly the reading I needed and did not ask for.

## The general shape

The distinctive thing here is that this is not a defect in the repository's
evidence discipline. Every gate passed, every digest matched, every number I
published was true of the tree I published. The defect is in the **substrate the
verification ran on**: a shared mutable working directory with four writers and
no lock, where git's own concurrency assumption — one index, one HEAD, one
operation at a time — was simply false.

`git worktree` exists precisely because that assumption is load-bearing. Four
agents each doing the locally reasonable thing (`git checkout -b my-branch`)
composed into an operation none of them intended.

The practice that follows, and the reason this is filed rather than just fixed:

- **Every parallel agent gets its own worktree, named in the prompt.** Not
  suggested — specified, with the command. I told five agents to work on five
  branches and left the isolation mechanism implicit, and four of them chose the
  one that shares state.
- **Read `%P` after any merge commit.** A merge that records one parent looks
  identical to a successful merge in `git log --oneline`, in `git show --stat`,
  and in the tree. It differs only in `%P` and in every future ancestry query.
- **Treat `Everything up-to-date` from a push as a failure signal**, not a
  no-op, whenever you believe you have just committed.

## Status

Fixed and read back, above. Filed because the near-miss is larger than the
miss: the content survived by coincidence, and the coincidence is not repeatable.
