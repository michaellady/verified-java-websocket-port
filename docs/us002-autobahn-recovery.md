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
| Ongoing-authorization diagnostic blocked receipt 3 | 22,640 | `7d8fa4df88188bcec74ea972c05efba421d30a75bc4528d394f6f61eecfaeec9` |
| Ongoing-authorization diagnostic blocked receipt 4 | 23,436 | `d341915c9b8f0b84afbc7ad1c2c9e4f06bee2e370089d286eaaf4f9aa36c4135` |
| Ongoing-authorization diagnostic blocked receipt 5 | 23,990 | `9679819438b6e66435b3b9bd362b0627ceb01657777b1733fb0f8a2285596b96` |
| Ongoing-authorization diagnostic blocked receipt 6 | 23,985 | `a45e36c26077dcae4b39d7c8f28c7b30f0744c9b7ce15b451703dd23f1b23533` |
| Ongoing-authorization diagnostic blocked receipt 7 | 23,985 | `e2ca2baf24e6eaea28bc3b0d828d441da1b2716a308452c6ef8840d0b935f883` |

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
| Preserve the fixed Autobahn HTTP authority across the loopback relay | The exact socket/authority split must be bound consistently for every case and report update | A stronger model still needs the protocol authority expected by the fixed suite endpoint | Exact argument validation and header transport contain no rerun or result-classification judgment | Code |
| Encode a verified peer TCP reset as terminal framed input | Concurrent byte transfer needs one deterministic terminal representation | A stronger model still needs the same kernel-to-frame transport mapping | Exact read-error classification only; Autobahn reports retain all protocol judgment | Code |
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

The next diagnostic invocation confirmed the release path repeatedly: server
mode durably materialized 32 per-case report directories before encountering a
separate relay attach completion race.

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
commit. The later correction below preserves both framed directions before it
closes the Docker stdin transport.

### Relay attach must close stdin after both directions, not after process wait

The server's thirty-second case failed after its relay had emitted
`RELAY_COMPLETE`; Docker attach nevertheless remained alive until its context
killed the CLI. The controller originally waited for attach stdout EOF and
process exit before closing the local stdin pipe. As with runner release, that
ordering can keep attach alive after the container process completes. Closing
stdin as soon as the input encoder finishes was already refuted because it can
drop response frames. The safe ordering is instead: consume the relay's
terminal framed output, wait for the loopback-to-relay encoder to finish its
own terminal END, close attach stdin, reject any bytes after the output END,
then wait for the attach process. Cancellation closes the loopback peer before
joining the encoder, and a separate 30-second post-output input bound remains.

A fake attach process that emits a complete framed response and then waits for
stdin EOF deadlocked before this correction and passes afterward. The existing
reverse-relay Docker canary also passes, proving response bytes are not
truncated. Controller-generated SHA-256/byte-count receipts for both raw
directions are now appended to failed relay lifecycle evidence; they do not
alter traffic or acceptance, and will distinguish a missing server response
from a Java handshake-classification problem in the next invocation.

That invocation proved the client relay was bidirectional: Java sent 209 raw
bytes (`sha256:e666d421098b903a10880b5fe0f0901d2d22ae336462fc69e25329a84cd83343`)
and received 107 raw bytes
(`sha256:1b2f5b9ee944424541b73f2fc515afa505721a6c99140102d85c37252c2ff593`).
The response did not complete Java's WebSocket open and produced no pre-open
exception. A bounded 512-byte maximum hex prefix of only the server-to-Java
handshake response is therefore added to failed transport evidence; payload
contents and Java-to-server request bytes remain unlogged.

The same invocation showed that attach may omit a final stderr lifecycle line
while preserving both raw directions. When the attached stream has an exact
paired role but lacks completion, the controller now polls only that exact
container's last 20 Docker log lines for up to five seconds and appends only an
exact `RELAY_COMPLETE role=...` or `RELAY_DENIED` marker—never mixed binary log
content. Missing or denied completion still fails closed.

### Client socket destination incorrectly became the HTTP Host authority

The fifth ongoing-authorization invocation retained the bounded response bytes
that Java received through the relay. They decode to an Autobahn HTTP 400:
the request's `Host` value was `127.0.0.1:<ephemeral relay port>`, which did not
match the fuzzing server's listening port 9001. This proves that container
identity, relay pairing, and both byte directions were correct; the remaining
client failure was the WebSocket client's default derivation of the HTTP
authority from its deliberately loopback socket URI.

The endpoint now keeps the actual connection destination as the exact loopback
listener while supplying the fixed suite authority `172.30.242.4:9001` as an
explicit, exactly validated `Host` header for both `runCase` and
`updateReports`. The controller supplies only that fixed value. The endpoint
self-test now observes and requires the overridden Host value, so a regression
to the loopback-derived authority fails before any suite process can start.
The source digest and resulting execution-plan digest changed accordingly; no
identity validation, network boundary, timeout, result interpretation, or
attempt accounting was relaxed.

### Verified peer resets were misclassified as relay corruption

The sixth invocation proved the Host correction: the fuzzing server returned
`HTTP/1.1 101 Switching Protocols`, Java completed the selected case exchange,
and the bounded server response ended with the expected data and close frames.
The relay then emitted `RELAY_DENIED transport`, which caused the controller to
cancel before Java's separate `updateReports` connection could succeed. In
server mode, case `3.4` again transferred both directions and retained exact
`RELAY_PAIRED` and `RELAY_COMPLETE` markers, yet the controller rejected the
otherwise successful attach. With decode, extra-output, process-exit, context,
and lifecycle conditions all successful, the remaining failed condition was
the loopback input reader's terminal reset.

Both directions had the same root cause: `ECONNRESET` from an already verified
TCP peer was classified as an infrastructure transport error. Autobahn cases
intentionally exercise protocol closes and drops, and their digest-bound
reports—not the relay—must classify those outcomes. Deterministic readers that
return bounded data followed by `ECONNRESET` reproduced both retained paths:
the in-container relay refused to emit framed END and the controller refused to
emit attached framed END. The smallest correction recognizes only
`ECONNRESET` on a read as end-of-stream, alongside EOF and an already-closed
socket. Writes, unknown read errors, malformed or trailing frames, missing
lifecycle evidence, identity drift, byte bounds, and report reconciliation
remain fail closed. The reset regressions explicitly prove that unknown read
errors are still rejected.

### Docker attach can omit the pairing marker as well as completion

The seventh invocation proved the reset correction at the process boundary:
both affected relays emitted `RELAY_COMPLETE`. The client attachment preserved
all 225 request bytes, all 214 response bytes, and the exact completion marker,
but omitted its earlier `RELAY_PAIRED role=dial` stderr line. The controller
therefore rejected the otherwise complete lifecycle and canceled before the
separate `updateReports` connection received a relay. Server case `3.4`
retained both lifecycle lines and both byte directions, but still failed one
terminal condition that the old evidence format did not name.

The relay role is already a closed controller input and part of the validated
container identity. Streaming attach now receives that exact expected role and,
when either lifecycle line is absent, polls only the exact container's last 20
log lines for up to five seconds. It appends only whole-line
`RELAY_PAIRED role=<expected>` and `RELAY_COMPLETE role=<expected>` markers, or
a whole-line, syntax-validated `RELAY_DENIED <reason>`; embedded substrings and
wrong roles do not satisfy lifecycle proof. Existing lifecycle validation was
also tightened from substring matching to exact lines. Failed attachments now
prefix bounded statuses for decode, input, extra output, trailing bytes,
process wait, context, and lifecycle validation, so another invocation can
identify the remaining server terminal field without exposing payloads or
loosening acceptance.
