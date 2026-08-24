# US-002 Autobahn recovery diagnosis

The first remediation through commit `5fd93474c064b845adece249d18ea9eefa24ee5f`
was diagnostic and non-live. After its reviewed handoff, Mike Lady explicitly
authorized further Docker debugging. The execution ledger conservatively
reserved exactly one additional combined controller invocation with no retry.
That invocation started both modes, completed zero cases, produced the retained
blocked receipt below, and exhausted the reservation. The PRD remains unchanged
and US-002 remains blocked.

## Retained receipt preservation baseline

| Receipt | Bytes | SHA-256 |
|---|---:|---|
| Original authoritative blocked receipt | 18,920 | `ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff` |
| Owner-authorized remediation blocked receipt | 20,123 | `ebb5157aa8ba6c7998dfce303acfbd5c4af166a8d377441e0709b481c26e44b2` |
| Owner-authorized recovery blocked receipt | 20,116 | `403e73b64ff7941795d23f0779b272582e7ab1d460eccc17cdf3602977d8a4b7` |

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
