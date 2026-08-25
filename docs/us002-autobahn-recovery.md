# US-002 Autobahn recovery diagnosis

The first remediation through commit `5fd93474c064b845adece249d18ea9eefa24ee5f`
was diagnostic and non-live. After its reviewed handoff, Mike Lady explicitly
authorized further Docker debugging. A later owner correction established that
the authorization is ongoing: as many individually bounded, accounted
client-plus-server diagnostic invocations may run as are genuinely needed.
Historical attempt records remain immutable, but the earlier agent inference of
a one-invocation cap was wrong. The PRD remains unchanged and US-002 remains
blocked while recovery continues.

## Retained receipt preservation baseline

| Receipt | Bytes | SHA-256 |
|---|---:|---|
| Original authoritative blocked receipt | 18,920 | `ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff` |
| Owner-authorized remediation blocked receipt | 20,123 | `ebb5157aa8ba6c7998dfce303acfbd5c4af166a8d377441e0709b481c26e44b2` |
| Owner-authorized recovery blocked receipt | 20,116 | `403e73b64ff7941795d23f0779b272582e7ab1d460eccc17cdf3602977d8a4b7` |
| Ongoing-authorization diagnostic blocked receipt 1 | 22,406 | `63eef8bf405d7b3623841f26a5499a6c21d236031ad35e7b173eca765eb3047a` |
| Ongoing-authorization diagnostic blocked receipt 2 | 22,540 | `81b8b91dea9894d01fa2a8e62d5f4dd003e8acea6926f7fd291bd1ccfb8654f4` |

These are hashes of the retained receipt bytes before the recovery edits. The
same files must be rehashed after remediation and review.

## Root causes established before production edits

### Runner container identity mismatch

The runner `docker run` command supplies the two closed runner variables with
`--env`. Docker resolves those explicit variables before the five variables
inherited from the pinned image. The validator required the same seven values
in the opposite order. A never-started, create-only fixture reproduced the
resolved order; no Autobahn process ran. The exact values, multiplicity,
entrypoint, image, mounts, resources, network, privileges, and publication
denial were correct. Environment order is not part of container identity, but
the exact environment multiset is.

### Server attach cleanup bound

When the fuzzing-client runner failed identity validation, server mode canceled
its per-case context. `exec.CommandContext` terminated `docker attach`, but
`runAttachedRelayTCP` then waited for the input encoder goroutine before closing
the loopback TCP connection that goroutine was reading. With the peer still
open, the read could remain blocked until the 180-second socket deadline, while
the caller allowed only 30 seconds for attach cleanup. A fake attach subprocess
and loopback-only test harness reproduces this without Docker or Autobahn.

## Primitive Test

| Capability | Atomicity | Bitter Lesson | ZFC | Verdict |
|---|---|---|---|---|
| Validate Docker `Env` as an exact order-independent multiset | Pure validation has no shared mutable state or read/write race | A stronger model still needs the same deterministic transport normalization | Exact parsing/comparison contains no recovery judgment | Code |
| Validate Docker tmpfs and bind mounts in their distinct inspect fields | Pure validation has no shared mutable state or read/write race | A stronger model still needs the same Docker transport representation | Exact parsing/comparison contains no recovery judgment | Code |
| Close canceled loopback transport before joining its reader | Cancellation and the concurrent reader require one deterministic ownership order | A stronger model still needs bounded process/socket cleanup | Process and socket lifecycle only; no retry or authorization judgment | Code |
| Stream and extract authenticated report bytes from runner tmpfs | The live tmpfs and host evidence directory require one bounded ownership and materialization protocol | A stronger model still needs the same byte transport and archive validation | Authentication, process I/O, byte bounds, and exclusive file creation contain no rerun judgment | Code |
| Authorize and deliver runner release without Docker attach EOF | Release must be atomic with report validation and exact single-use token consumption | A stronger model still needs a deterministic authenticated process-control transport | Exact token input, O_EXCL marker creation, fixed signal delivery, and bounded cleanup contain no rerun judgment | Code |
| Decide whether another live attempt is warranted or authorized | Owner/assurance decision, not an atomic transport primitive | Better reasoning can change the decision | Contains acceptance and risk judgment | Prompt/owner decision |

The code changes therefore remain limited to deterministic identity
normalization and transport cleanup. Attempt authorization and rerun judgment
remain outside the binary.

## Recovery-run root cause established before the next production edit

The recovery receipt advanced past environment validation and exposed
`AUTOBAHN_RUNNER_CONTAINER_IDENTITY_MISMATCH` at
`$.runner.container.mount`. A never-started create-only fixture using the exact
runner mount arguments reproduced Docker 29.7.2's resolved inspect shape:
`HostConfig.Tmpfs` contains `/tmp` and `/reports`, while `.Mounts` contains only
the `/config` and `/autobahn-runner` bind mounts. The validator already checks
the complete tmpfs map and exact options, but then incorrectly required those
same tmpfs entries to appear again in `.Mounts`. The reported "undeclared or
anonymous mount" detail was therefore a false classification of two missing
duplicate records, not proof of an anonymous volume. The fixture remained in
`created` state with PID zero and was removed with its volumes.

The smallest fail-closed correction is to keep the exact `HostConfig.Tmpfs`
validation and validate `.Mounts` as exactly the two read-only bind mounts.
Missing, added, anonymous, writable, or source-substituted bind mounts remain
rejected. A retained-inspect regression using Docker's actual representation
failed before this production change.

## Ongoing-authorization diagnostic root causes

### Docker reports a successful copy from tmpfs but copies no files

The next combined diagnostic reached both accepted Autobahn processes. Server
mode ran case `1.1.1`, the fuzzing client exited zero, and the relay completed,
but the host report directory remained empty after `docker cp`. A separate
network-none, read-only, capability-dropped container fixture wrote a marker to
`/reports` on tmpfs. Docker 29.7.2 returned success from `docker cp
container:/reports/. destination`, yet the destination did not contain the
marker. The fixture ran no Autobahn mode and was removed with its volumes.

The correction keeps `/reports` as a 256 MiB, noexec/nosuid/nodev tmpfs. The
qualified Go runner now exposes one fixed `copy-reports` operation through
`docker exec`. It authenticates the existing 64-hex token on stdin, revalidates
the pinned runner environment and artifacts, and emits a deterministic USTAR
stream containing exactly four singly-linked top-level regular files. Per-file
and aggregate bounds remain 64 MiB and 256 MiB. The controller accepts only the
four case-specific names, USTAR regular files, mode 0400, exclusive creation in
a fresh mode-0700 host directory, complete archive consumption, the exact
runner lifecycle marker, and zero trailing stdout bytes before releasing the
primary runner. No shell, writable host bind, extra network, or public port was
introduced.

A non-Autobahn Docker fixture exercised the compiled Linux runner against a
tmpfs containing four reports. The authenticated command emitted the exact
lifecycle marker and a 5,120-byte four-member archive, then the fixture and its
tmpfs were removed. Unit regressions reject the retained empty result as well
as partial sets, directories, symlinks, path escapes, non-USTAR members, and
oversized members.

The following diagnostic invocation proved this correction against an actual
Autobahn-generated server report: all four expected files were materialized in
the host evidence directory. Server mode then failed only at the separate
runner-release step.

### Docker attach does not deliver the EOF required by exact runner release

The runner originally read its 64-hex release token plus newline with a bounded
`ReadAll`, deliberately rejecting missing, wrong, or trailing bytes. Docker
`attach` accepted the token bytes from the controller but did not close the
container stdin stream when the local reader reached EOF. The 30-second release
context therefore killed the attach command, even though report extraction had
succeeded. A separate network-none container running only `stdin.read()`
reproduced the behavior: the bounded attach client had to be killed and the
container remained blocked with no output. It was then removed with its
writable layer.

Runner primary stdin is now closed in the container identity. Release uses a
fixed authenticated `docker exec --interactive ... /autobahn-runner release`;
the exec process receives real stdin EOF, revalidates the pinned artifacts and
configuration, and durably creates one O_EXCL, mode-0400 marker containing only
the SHA-256 binding of the token. After the exec exits successfully, the
controller sends `USR1` to the exact validated container name. PID 1 consumes
and deletes the exact singly-linked marker before stopping or releasing the
child. Wrong, reused, linked, missing, or malformed markers fail closed. The
controller then requires exit zero and the primary runner completion marker.

A network-none, read-only, capability-dropped Docker fixture exercised the
compiled release subcommand, verified the marker binding in its PID 1 signal
handler, and exited zero only after the authenticated exec followed by exact
signal delivery. The fixture and tmpfs were removed. This eliminates runner
`docker attach` without changing report bounds, network isolation, or token
placement on stdin.

### Client relay failure was hidden by error discard

The same diagnostic showed that the Java client did not complete its first
WebSocket handshake, while the fuzzing server was ready. On that failure path,
the controller canceled and joined the relay-session goroutine but discarded
its returned error, so the retained receipt could not distinguish dial timeout,
attach framing failure, or bounded cleanup failure. The controller now records
that relay terminal result ahead of bounded endpoint and runner logs. This is
an evidence correction, not a retry or timeout relaxation. The next accounted
invocation will use that evidence to establish the client transport root cause
before changing its behavior. The following invocation showed that the dial
relay reached `RELAY_COMPLETE`; cancellation killed the still-attached Docker
CLI only after the Java 10-second handshake timeout. The adapter's `onError`
callback had intentionally suppressed protocol errors, but that also discarded
the pre-open connection exception needed for diagnosis. It now retains only a
bounded pre-open exception class/message and continues to ignore post-open
protocol errors, leaving Autobahn reports authoritative. No timeout was
increased and no protocol result classification changed.

An experiment that closed relay attach stdin immediately after the framed END
marker was rejected: the existing non-live reverse-relay canary proved Docker
detached before returning the response frames. That change was reverted before
commit. Relay attach byte transport therefore remains unchanged while the next
accounted invocation captures the actual Java handshake exception.
