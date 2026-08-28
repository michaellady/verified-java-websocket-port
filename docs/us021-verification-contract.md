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
properties and seed replays remain authoritative inputs; one US-021 aggregation
test adds deterministic cross-seam schedules and a closed target inventory.

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
profile, command, source tree, and output digest. Each admitted platform runs
debug and release suites twice with an outer deadline, reconciles process exit
and test counts, and records file-descriptor and child-process cleanup checks.
Linux execution is distinct from compilation or emulation and may not be
inferred from either.

Miri, sanitizers, ThreadSanitizer, `cargo-fuzz`, and other race/fuzz engines are
accepted only when the pinned toolchain actually identifies and executes them.
An unavailable tool is recorded as unavailable and contributes no pass or
race-freedom claim. The owner-relaxed story can still pass from the in-tree
bounded engine and two blocking-platform runtime receipts, but the manifest and
PRD must retain the missing external-tool nonclaims.

## Failure handling

Campaign subprocesses have fixed deadlines and output ceilings. Nonzero exit,
signal, timeout, panic, OOM, malformed output, digest drift, differing repeat
results, leaked descriptor/process canaries, or a surviving planted failure
fails the manifest. Public-safe failures are minimized to the existing seed
format and committed under the owning Rust crate; protected inputs remain
digest-only and are never copied into public evidence.

## Explicit nonclaims

- no unbounded property, fuzz, state-space, panic-freedom, or race-freedom proof;
- no hidden or sealed corpus disclosure;
- no live Autobahn, Docker/wstest conformance, or consumed-attempt rerun;
- no claim for an unavailable cargo-fuzz, Miri, sanitizer, or race-tool run;
- no production, publication, signing, or independent-review claim;
- assurance remains `OWNER_ATTESTED_NOT_INDEPENDENT`.
