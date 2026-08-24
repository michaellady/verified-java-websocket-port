# US-002 Autobahn recovery diagnosis

This remediation is diagnostic and non-live. It does not run either Autobahn
mode, alter attempt accounting, change the PRD, or authorize another attempt.

## Retained receipt preservation baseline

| Receipt | Bytes | SHA-256 |
|---|---:|---|
| Original authoritative blocked receipt | 18,920 | `ca942585442eb4be74a62533fa2b44a985970612ce6f69d5c13df8ede83c6cff` |
| Owner-authorized remediation blocked receipt | 20,123 | `ebb5157aa8ba6c7998dfce303acfbd5c4af166a8d377441e0709b481c26e44b2` |

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
| Close canceled loopback transport before joining its reader | Cancellation and the concurrent reader require one deterministic ownership order | A stronger model still needs bounded process/socket cleanup | Process and socket lifecycle only; no retry or authorization judgment | Code |
| Decide whether another live attempt is warranted or authorized | Owner/assurance decision, not an atomic transport primitive | Better reasoning can change the decision | Contains acceptance and risk judgment | Prompt/owner decision |

The code changes therefore remain limited to deterministic identity
normalization and transport cleanup. Attempt authorization and rerun judgment
remain outside the binary.
