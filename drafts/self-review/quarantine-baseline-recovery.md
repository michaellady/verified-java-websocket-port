# The pinned Java-WebSocket baseline is recoverable here, and the archive digest verifies

Two firings ago I recorded that `.quarantine/` was empty "because the pinned
Java source is absent and the GitHub archive endpoint is proxy-refused". F011
corrected the first half: the quarantine was a tracked symlink pointing at
itself, so it could not hold anything. This corrects the second half. The
endpoint refusal was real but it was not a network wall, and the archive digest
was verifiable the whole time.

## Result

**All five pinned Java-WebSocket artifacts now verify at their declared sha256
and byte size**, re-hashed from the stored quarantine copies rather than from
the fetch that produced them:

```
MATCH  java-websocket-source-archive  size=190008 (pin 190008)
MATCH  java-websocket-license         size=1082   (pin 1082)
MATCH  java-websocket-source-pom      size=13425  (pin 13425)
MATCH  java-websocket-runtime-jar     size=140686 (pin 140686)
MATCH  java-websocket-runtime-pom     size=13737  (pin 13737)

5/5 pinned Java-WebSocket artifacts verified from the quarantine copies
```

The source tree is extracted at
`.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667`, which is
byte-for-byte the path `assurance/concurrency/plan.json:15` declares as
`quarantine_tree`.

## The 403 was a repository-scope gate, not a network block

`curl` on the pinned `immutable_url` returns HTTP 403 with a 378-byte JSON body,
and the body is the whole story:

> GitHub access to this repository is not enabled for this session. Use
> add_repo to request access.

That is an actionable, documented remedy, not a refusal. `add_repo` for
`TooTallNate/Java-WebSocket` answered that read access was already available —
the session's git proxy serves anonymous git reads of public GitHub repositories
directly. So the codeload archive URL stays 403, and the git protocol works.

I had read one 403 as "the endpoint is proxy-refused" and stopped. The body said
otherwise and I had not read it. Reading the body of a failure is the same
discipline as reading the stack of a test failure, which a parallel agent
applied earlier today to avoid writing up a 600-second timeout as a defect.

## The archive digest reproduces, and this is the part I expected to fail

A parallel branch disclosed that it had matched the pin's provenance TREE hash
via `git cat-file` and materialised with `git archive`, and had NOT verified the
declared archive sha256 — correctly flagging those as different checks. I
expected the archive digest to be unreproducible: GitHub's codeload tarballs are
not generally byte-reproducible from a local `git archive`, and tar/gzip output
turns on entry order, mtimes, uid/gid, modes, compression level and the gzip
header's embedded filename and timestamp.

It reproduces exactly. Separating the tar bytes from the gzip bytes is what
found it:

```
git archive --format=tar.gz --prefix=Java-WebSocket-da3cf2a.../ v1.6.0
    size=189807  sha256=621ff8e0…                       NO

git archive --format=tar --prefix=Java-WebSocket-da3cf2a.../ v1.6.0
    tar size=1935360  sha256=973e0715…
  | gzip -9n   size=185350  sha256=425ad16e…            NO
  | gzip -6n   size=190008  sha256=f44e7647b4aee408…    *** MATCH ***
```

`gzip -6n` — level 6, no embedded name or timestamp — over `git archive`'s tar,
with GitHub's `<repo>-<full sha>/` prefix. Both the pinned sha256
`f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4` and the
pinned `byte_size` 190008, exactly. The single-step `--format=tar.gz` misses
because git's own gzip call differs; the pipeline hits.

So the pinned digest IS a digest of a `git archive`-reproducible tarball, and
the tree-hash route and the archive-digest route both close. That is a stronger
position than either branch had, and I am recording the level and the `-n` flag
because they are the whole of it.

## A check of mine that was wrong, and how it was caught

I first verified the extracted tree by `git add -A` + `git write-tree` in a
scratch repo and got `75798583b459dbf87134f2cca133eb6ab05b242c` against the
pinned `30c108fd7b68663f645ee9cb8e3daaf4a39235ea`. A mismatch.

The archive digest had already matched exactly, so one of the two readings was
wrong, and I did not get to pick. Two candidate explanations: `.gitattributes`
`export-ignore` (the usual cause of archive-vs-tree divergence), or a fault in
my check. Both were testable:

- `git show v1.6.0:.gitattributes` → `fatal: path ... does not exist`. No
  export-ignore.
- File sets compared: **204 files in the git tree, 204 in the archive, and
  `comm -23` empty** — nothing in the tree is missing from the archive.

So the archive was complete and my check was the fault: `git add -A` honours
`.gitignore`, and Java-WebSocket ships one, so files that git TRACKS were being
skipped from my index. The direct check is content, not a re-derived tree:

```
files compared: 204
missing from the extracted tree: 0
content mismatches: 0
VERDICT: every tracked file in the pinned git tree is byte-identical on disk
```

per-file SHA-1 over `blob <len>\0<bytes>` against `git ls-tree -r v1.6.0`. Had I
reported the `write-tree` mismatch as a finding, it would have been a defect in
my own instrument published as a defect in the artifact.

Also verified from upstream git, against the pin's own `provenance` string
("git commit da3cf2a… tree 30c108fd… tag v1.6.0"): `git rev-parse v1.6.0^{commit}`
= `da3cf2a777aed862f2f5b5cf060cae7969958667` and `v1.6.0^{tree}` =
`30c108fd7b68663f645ee9cb8e3daaf4a39235ea`. All three components match.

## Still blocked, with the exact reason

**RFC 6455 text** (`third_party/rfc6455/rfc6455.txt`, pin sha256
`765775326aee0ecca9b04bde3fd1f52932d498e33e34e428bd61b8a24da0fa3b`, 162067
bytes). This one gates real work: rank-1 oracle binding, and verification of
rank 3's fifteen deciding rules, both recorded as blocked on it.

Three canonical hosts all fail at the tunnel, not the endpoint:

```
https://www.rfc-editor.org/rfc/rfc6455.txt      curl (56) CONNECT tunnel failed, response 403
https://www.ietf.org/rfc/rfc6455.txt            http=000
https://datatracker.ietf.org/doc/rfc6455/doc.txt http=000
```

Same class as `api.adoptium.net:443`, which the proxy's own status endpoint lists
under `recentRelayFailures` as "gateway answered 403 to CONNECT (policy denial
or upstream failure)" — twice today. This is a policy denial on the host, and it
is NOT the repository-scope gate that `add_repo` fixes.

`raw.githubusercontent.com` IS reachable, so a GitHub-hosted copy would work.
Four plausible mirror paths returned 14-byte `404: Not Found` bodies. I stopped
there rather than keep guessing paths: for a digest-pinned artifact the digest
is the authority and the URL is not, so any source hashing to
`765775326aee…` satisfies the pin — but a *near* miss substituted for the pin
would be worse than an honest gap, and guessing raises that risk with every
attempt.

**OWNER ACTION**, either form: commit the RFC text to
`third_party/rfc6455/rfc6455.txt` (the digest is self-verifying, so provenance
travels with the bytes), or name a reachable host and let the pin's own replay
step check it.

**JDK 17.0.19.** Unchanged and I expect it to stay that way. `api.adoptium.net`
is CONNECT-403'd. The pin is a Homebrew bottle at
`ghcr.io/v2/homebrew/core/openjdk/17/blobs/sha256:6d51e51e…`; `ghcr.io/v2/`
answers 401, so the host is reachable but needs a token exchange. I did not
pursue it, and the reason is not effort: a Homebrew bottle is platform-specific,
and this session is Linux x86_64. Obtaining a darwin bottle would not produce a
runnable JDK 17 here. `java -version` reports **openjdk 21.0.10**.

**So any live-Java reading taken in this session is still NOT a pinned-baseline
reading**, and the recovery above does not change that. What it changes is that
the pinned SOURCE is now present and digest-verified, so a reading on OpenJDK 21
is at least against the right bytes — the JDK is the one remaining substitution,
and it should be named every time rather than folded into a green result.

## The JDK pin is enforced on one path and not on another

Populating the quarantine did NOT fix the two declared baseline failures, and
what they fail on is worth recording rather than filing under "environment":

```
internal/portplan  FAIL  TestDeriveReproducesCommittedEvidence
    JAVAC_UNAVAILABLE: javac reports "... javac 21.0.10", pinned JDK is 17.0.19
internal/portplan  FAIL  TestDeriveFailsOnDeclarationLevelOracleTamper
    a declaration-level tamper must fail closed with ORACLE_REPRODUCTION_MISMATCH,
    got JAVAC_UNAVAILABLE ... pinned JDK is 17.0.19
internal/lab       FAIL  TestControlledCanaryRequestIsClosedAndRequiresAuthenticatedPromotions
    PLATFORM_EXECUTOR_UNSUPPORTED at $.controlled_canary: CONTROLLED_CANARY requires Darwin sandbox-exec
```

Neither mentions the quarantine. `internal/lab` needs Darwin `sandbox-exec`, a
platform gate. And `internal/portplan` **refuses to derive on the wrong JDK, by
name and by version**. That is the pin being enforced, working exactly as
designed — a fail-closed refusal, not a defect.

Which raises the asymmetry. The live-Java differential and the handshake exam
BOTH ran to completion on OpenJDK 21 in this session and reported 74/74 and
49/49. `internal/portplan` will not derive at all on OpenJDK 21. So the
repository has two paths that consume a live Java oracle, and **only one of them
checks the JDK against the pin**.

The second `portplan` failure sharpens it further: a test whose subject is a
declaration-level oracle TAMPER cannot even reach its assertion, because the
JDK check fires first. Its intended finding (`ORACLE_REPRODUCTION_MISMATCH`) is
unreachable on this host. That check is not being exercised here at all, and a
green run of the packages around it says nothing about whether it works.

I am not proposing that the exam paths adopt `portplan`'s refusal — that would
turn every live-Java reading in this session into a hard stop, which is a call
for the owner, not a change to make in passing. What should not survive is the
current state, where the same substitution is fatal in one place and silent in
another, and the silent one is where the headline numbers come from.

Recorded as an owner question rather than fixed: should a live-Java reading taken
on a non-pinned JDK be refused, or admitted with a mandatory non-baseline label
that travels with the number? Today it is admitted with a label applied by
whoever remembers.

## What I did not do

- Did not fetch the Autobahn source archive, license or case registry, the OCI
  image, Maven, any Rust toolchain component, or the developer tools. All are
  pinned in `evidence/intake/source-pins.json` and several are now plausibly
  reachable by the same route; none was needed for the Java baseline.
- Did not commit any quarantine content. `.gitignore:30` covers `.quarantine/`
  and, since F011 untracked the symlink, that rule works as authored. The
  artifacts are local to this container and reproducible from the commands above.
- Did not run Autobahn, AWS or a benchmark. No owner gate crossed.
- Did not re-baseline anything. No corpus, denominator or count was touched.
