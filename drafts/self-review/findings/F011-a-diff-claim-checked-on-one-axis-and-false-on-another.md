# F011 — a diff claim checked on the axis it was about, and false on the axis it asserted

## The claim

`f1b98a4` ("linkage: refreeze after the io_loop.rs edit") states, in its own
commit message:

> The diff is FIVE digest lines and nothing else.

Every word about the digests is true and was checked. Each of the five lines is
io_loop.rs's new sha256 `1926916e73290a84…`, each was compared against
`sha256sum` of the real file, no line number moved, no declaration text changed,
no symbol lost a binding, no verification flag flipped. That verification is
sound and I have no correction to make to it.

## What was not checked

`git show --name-status --format="" f1b98a4`:

```
A	.quarantine
M	evidence/linkage/evidence-dag.json
M	evidence/linkage/rust-identity-verification.json
```

Three files, not two. "Nothing else" is a claim about the **file set**. It was
verified against the **digest lines**. Those are different axes, and the
sentence asserts the one that was never measured.

## What the unchecked file was

```
120000 449d870f8936f53ec73349d44b325184bae344f3 0	.quarantine
lrwxrwxrwx .quarantine -> /home/user/verified-java-websocket-port/.quarantine
```

Mode `120000` is a symlink, and its target is its own absolute path. A
self-referential symlink, committed into the tree.

`.gitignore:30` already reads `.quarantine/`. The intent was always an ignored
working directory holding the pinned Java source, the jars, and the extracted
archive. But **a tracked path overrides `.gitignore`**, so git materialised the
symlink on every checkout and the directory could never exist. Nothing could be
written into it, because every write resolved back to the link itself.

## What it cost

This is the mechanism behind an environment failure I had already recorded, and
recorded with the wrong cause. I wrote that the quarantine was empty because the
pinned Java source was absent and the GitHub archive endpoint was proxy-refused.
The proxy refusal is real. It is not why the quarantine is empty. The quarantine
is empty because it is not a directory. I had the nearest available explanation
and stopped there — F008's class, committed by me, against my own record.

Downstream, in three separate places:

- `internal/portplan TestDeriveReproducesCommittedEvidence` was noted in
  `drafts/borrow-receipt-batch-c.json` as a "first-run `.quarantine`
  materialization" flake that passed on re-run. It is not a flake.
- `assurance/concurrency/plan.json:15` names
  `.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667` as its
  quarantine tree. That path cannot exist.
- `drafts/us018-closure-receipt.json:76` invokes `crosspeerctl` with
  `-jar .quarantine/Java-WebSocket-1.6.0.jar`. Same.

Three sightings, none of which reached the cause, because each had a local
story that fit.

## The fix

```
git rm --cached .quarantine && rm -f .quarantine
```

Read back:

- `git ls-files .quarantine` — empty; no longer tracked.
- `mkdir -p .quarantine && echo probe > .quarantine/probe.txt && cat` — `probe`.
  The directory is now writable, which it has not been since `f1b98a4`.
- `git check-ignore -v .quarantine/probe.txt` — `.gitignore:30:.quarantine/`,
  exit 0. The ignore rule works as authored, now that nothing shadows it.
- `git status --short --untracked-files=all .quarantine` — only the `D` for the
  removed symlink.

This does not obtain the pinned Java source. The archive endpoint is still
proxy-refused and JDK 17.0.19 is still gone, so live-Java readings remain
non-baseline readings. It removes the reason the source could not be stored even
if it were fetched.

## The general shape

F010 was fidelity standing in for correctness: DIV-06 verified exhaustively
against Java and never against the story criterion. This is narrower and worse,
because the false sentence and the true verification are in the same paragraph.
The check ran on the axis the author was thinking about. The claim was written
about a wider axis. Nothing in between compared the two.

`git show --name-status` costs one command and would have caught it. The
practice that follows: a commit message that says "and nothing else" is making a
claim about the file set, and the file set is the thing that must be read back
before that sentence is written.

## Status

Fixed and read back, above. Filed because the fix is one line and the reading
error behind it is not.
