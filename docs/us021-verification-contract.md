# US-021 property, fuzz, and runtime verification contract

US-021 closes the public verification layer around the Rust port without adding
a second protocol implementation or weakening the dependency-free production
workspace. Its evidence is finite, replayable test evidence, not proof.

## Deep module boundary

`internal/campaign` is the sole Go evidence facade. It reads three closed
manifests, rederives every repository-file and corpus identity, validates the
fixed target inventory and platform receipts, and rejects missing, extra,
duplicate, stale, unavailable-as-pass, or overclaimed evidence. The small
`campaignctl verify` CLI exposes only that operation.

The actual protocol campaigns remain in Rust integration tests and call the
public `websocket_core` and `websocket_driver` APIs. They never copy protocol
parsers or frame logic into an evidence tool. Existing US-010 through US-017
properties and seed replays remain authoritative inputs; US-021 freezes their
closed inventory without adding a second Rust campaign implementation.

## Fixed target inventory

Property evidence covers these exact invariants:

1. semantic encode/decode round trips and canonical lengths;
2. mask equation and involution;
3. transport chunk-boundary invariance;
4. admission before allocation and queue limits;
5. strict UTF-8 across transport and fragment boundaries;
6. fragment/control ordering;
7. close and terminal delivery at most once;
8. deterministic owner-schedule replay.

Fuzz evidence covers these exact public seams:

1. client handshake;
2. server handshake;
3. frame decode;
4. message and UTF-8;
5. fragment and control sequences;
6. close and EOF;
7. owner command/byte schedules.

Each target binds its Rust test source, replay command, bounded case count,
deterministic engine seed/version, seed paths and aggregate corpus digest,
timeout/OOM/crash disposition, and two reconciled observations. A target cannot
pass from a declared command or static corpus alone.

## Runtime evidence

Runtime receipts are keyed by exact OS, architecture, Rust compiler identity,
profile, command, and immutable Git source tree. Each admitted platform records
two debug and two release executions, reconciled process exit and test counts,
and owner-observed file-descriptor and child-process cleanup checks. Linux
execution is distinct from compilation or emulation and may not be inferred
from either. These receipts remain owner-attested; the verifier does not claim
to independently re-execute or reconstruct their process output.

Miri, sanitizers, ThreadSanitizer, `cargo-fuzz`, and other race/fuzz engines are
accepted only when the pinned toolchain actually identifies and executes them.
An unavailable tool is recorded as unavailable and contributes no pass or
race-freedom claim. The owner-relaxed story can still pass from the in-tree
bounded engine and two blocking-platform runtime receipts, but the manifest and
PRD must retain the missing external-tool nonclaims.

## Failure handling

`campaignctl` launches no campaign subprocesses. It fails closed when a receipt
declares a nonzero exit, timeout, panic, hang, leak, flake, unresolved failure,
identity drift, differing fixed command, or incomplete repeat inventory. The
execution operator remains responsible for process deadlines and bounded
output capture. Public-safe failures are reduced to an existing test seam and
retained in the remediation record; protected inputs remain digest-only and
are never copied into public evidence.

## Explicit nonclaims

- no unbounded property, fuzz, state-space, panic-freedom, or race-freedom proof;
- no hidden or sealed corpus disclosure;
- no live Autobahn, Docker/wstest conformance, or consumed-attempt rerun;
- no claim for an unavailable cargo-fuzz, Miri, sanitizer, or race-tool run;
- no production, publication, signing, or independent-review claim;
- assurance remains `OWNER_ATTESTED_NOT_INDEPENDENT`.
