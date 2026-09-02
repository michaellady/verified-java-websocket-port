(part 7b of 7) Java-WebSocket child laboratory PRD, child stories US-009 through US-019.

### US-009 — Establish the safe Rust ConnectionCore contract
**Priority:** 2 | **Passes:** true | **Depends on:** US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008 | **Labels:** implementation, rust, architecture, safe-rust

As a Rust maintainer, I want one deep deterministic Sans-I/O interface before protocol slices so that networking, runtime, proof, and oracle adapters cannot duplicate protocol state.

**Acceptance criteria:**
- Before any file write, a separately authorized repository handoff binds metadata.repoPath to a non-HQ git root whose remote owner/name, default branch, license, and immutable authorization receipt agree with the laboratory manifest and program registry; absence or mismatch leaves this story BLOCKED. The bound workspace enforces #![forbid(unsafe_code)] for every first-party crate, inventories dependency unsafe separately, and configures formatting, Clippy with warnings denied, debug/release tests, minimum supported Rust version, license, audit, reproducible lockfile gates, and good/bad scaffold canaries. Under the owner relaxation accepted on 2026-08-26, dependency-free first-party development, tests, review, and audit may run on the exact pinned host toolchain; any build.rs, proc macro, external dependency build, newly acquired audit executable, or other hostile/dependency-bearing workload must execute through the accepted US-007 Docker sbx profile, and final promoted evidence must replay the complete Rust gate in that profile before US-019 or release acceptance. This story claims interface and infrastructure only.
- ConnectionCore accepts immutable ConnectionConfig, Role, TransportBytes, and LocalCommand and returns ordered TransportWrite, SemanticEvent, ConnectionState, and TypedProtocolFailure values without opening sockets, reading clocks, or invoking callbacks.
- Configuration includes explicit handshake, frame, message, buffered-byte, event, command-queue, and write-queue limits with checked conversions and deterministic defaults; zero, boundary, and oversized values are tested.
- One mutable connection owner and bounded multi-producer command channel are the only concurrency boundary; the core remains deterministic under arbitrary byte chunking and exposes backpressure rather than unbounded allocation. Handshake or frame behavior cannot be marked complete by this story.

### US-010 — Implement the client opening-handshake slice
**Priority:** 2 | **Passes:** true | **Depends on:** US-009 | **Labels:** implementation, handshake, client, vertical-slice

As an RFC 6455 client, I want deterministic incremental request generation and response validation so that the connection opens only after a valid server upgrade.

**Acceptance criteria:**
- The client generates a GET HTTP/1.1 upgrade request with a promoted randomness seam for a 16-byte Sec-WebSocket-Key, version 13, required tokenized headers, caller resource descriptor, and deterministic normalized semantic output.
- Response parsing accepts arbitrary byte chunk boundaries and validates status 101, Upgrade and Connection tokens, exact Sec-WebSocket-Accept derivation, declared subprotocol absence, and configured handshake/header limits before transitioning Open.
- Malformed status lines, missing/duplicate/invalid required headers, wrong accept values, unsupported extensions/subprotocols, partial EOF, extra bytes, and oversized inputs produce stable typed failures and never deliver application data.
- RFC-derived public/hidden vectors and Java differential observations cover valid and invalid behavior; any Java/RFC mismatch is added to the delta ledger rather than copied.
- The migration map, compatibility surface, tests, properties, fuzz seeds, runtime assertions, and evidence DAG link to the exact shipped client handshake symbols.

### US-011 — Implement the server opening-handshake slice
**Priority:** 2 | **Passes:** true | **Depends on:** US-009, US-010 | **Labels:** implementation, handshake, server, vertical-slice

As an RFC 6455 server, I want incremental request validation and deterministic upgrade responses so that only an allowed client handshake opens the connection.

**Acceptance criteria:**
- The server incrementally parses GET HTTP/1.1 requests and validates method/version, resource descriptor, Host presence, Upgrade and Connection tokens, version 13, base64 16-byte key semantics, absent excluded extensions, and configured byte/header limits.
- A valid request emits a deterministic 101 response with the exact Sec-WebSocket-Accept, required headers, no Java-specific Date or Server banner, and a normalized semantic handshake event.
- Wrong methods/versions, malformed request lines, invalid or duplicate required headers, unsupported versions/extensions/subprotocols, partial EOF, smuggling-shaped lines, control characters, and oversized inputs fail before Open.
- RFC-derived, independent-parser, and Java differential vectors cover valid and invalid paths with arbitrary chunking; Java leniency cannot lower the RFC gate.
- All handshake cases reconcile and link to migration rows, property/fuzz/runtime evidence, delta decisions, and the shipped server handshake symbols.

### US-012 — Implement canonical framing, masking, and allocation limits
**Priority:** 2 | **Passes:** true | **Depends on:** US-009 | **Labels:** implementation, framing, masking, formal, limits

As either WebSocket role, I want incremental frame headers and payloads decoded and encoded safely so that masking, lengths, control constraints, and caps match RFC 6455 before allocation.

**Acceptance criteria:**
- The exact shipped decoder and encoder implement canonical 7-, 16-, and 64-bit payload lengths, checked conversions/arithmetic, incomplete buffering across arbitrary chunks, opcode/FIN/RSV extraction, and configured pre-allocation frame/buffer caps.
- Client writes are masked and server writes are unmasked; server input requires masking and client input rejects masking; the repeating four-byte XOR equation and unmask round trip hold for every tested offset and chunking.
- Reserved bits/opcodes, noncanonical lengths, 64-bit high bit, invalid role masking, fragmented or oversized control frames, control payloads over 125 bytes, overflow, EOF, and over-cap inputs produce stable protocol failures without panic or unbounded allocation.
- Autobahn categories 1, 3, 4, and 10 plus neutral differential/property/fuzz/runtime cases exercise the exact shipped symbols; Java's known unmasked-input leniency is classified as a quirk, not emulated.
- Actual-code formal runs prove or bounded-check the declared mask/header obligations with exact identities, nonzero obligations, good/bad canaries, artifacts, assumptions, bounds, and replay at no higher than the executed ceiling.

### US-013 — Deliver strict text and binary messages
**Priority:** 2 | **Passes:** true | **Depends on:** US-012 | **Labels:** implementation, messages, utf8, vertical-slice

As an application, I want valid text and binary frames delivered as typed events so that UTF-8 and message boundaries are correct under arbitrary transport chunking.

**Acceptance criteria:**
- Final binary frames deliver byte-exact Binary events and final text frames deliver Text only after strict complete UTF-8 validation; frame events precede message events in the normalized order.
- Incremental UTF-8 state handles code points split across transport chunks and reports invalid, overlong, surrogate, out-of-range, truncated, and otherwise noncanonical sequences with the RFC close/error semantics.
- Message, buffered-byte, and event limits are checked across input chunks before growth; zero-length, exact-boundary, and over-boundary payloads are covered without panic or silent truncation.
- Autobahn categories 1 and 6, neutral Java/Rust differential scenarios, properties, fuzz targets, and runtime checks all invoke the shipped message/UTF-8 path and reconcile exactly.
- Seeded UTF-8 leniency, event-order, truncation, and limit defects are killed and retained as regression cases.

### US-014 — Reassemble fragmented messages with bounded state
**Priority:** 2 | **Passes:** true | **Depends on:** US-012, US-013 | **Labels:** implementation, fragmentation, limits, vertical-slice

As an application, I want fragmented data messages reassembled while control frames interleave so that legal sequences deliver once and illegal or oversized sequences fail deterministically.

**Acceptance criteria:**
- A non-final text/binary frame begins exactly one fragmented message; continuation frames append in order and the final continuation delivers one typed message while preserving strict incremental UTF-8 state for text.
- Ping, pong, and close control frames may interleave without changing fragmented-message state; a new data frame during fragmentation or continuation without an active sequence is a protocol failure.
- Whole-message and buffered-byte caps are checked with overflow-safe accumulated lengths before allocation; fragmented zero-length, exact-limit, over-limit, EOF, and reset paths release state predictably.
- Autobahn category 5 and neutral Java/Rust differential/property/fuzz/runtime scenarios cover every transition and arbitrary transport chunking with exact reconciliation.
- Seeded state-reset, control-interleaving, UTF-8-boundary, double-delivery, and accumulated-limit mutants are killed and preserved.

### US-015 — Implement ping and pong control behavior
**Priority:** 2 | **Passes:** true | **Depends on:** US-012, US-014 | **Labels:** implementation, ping-pong, control, vertical-slice

As a connected peer, I want ping and pong control frames handled without corrupting data state so that liveness signals remain deterministic and observable.

**Acceptance criteria:**
- A valid inbound ping emits a Ping semantic event and a pong write with byte-identical payload according to the configured automatic-response policy; inbound pong emits one Pong event and no automatic data write.
- Control frames interleave during fragmentation, remain final, unfragmented, uncompressed, and at most 125 bytes, and do not alter UTF-8 or data-message accumulation.
- Outbound local ping/pong commands obey Open/Closing state rules, queue/backpressure limits, payload caps, and deterministic event/write ordering.
- Autobahn category 2 plus Java/Rust differential, property, fuzz, and runtime scenarios cover empty/boundary/oversized payloads, arbitrary chunking, interleaving, and invalid control flags.
- Seeded payload-loss, wrong-opcode, unwanted-reply, state-corruption, and limit mutants are killed and retained.

### US-016 — Complete close, EOF, and terminal-state behavior
**Priority:** 2 | **Passes:** true | **Depends on:** US-012, US-013, US-014, US-015 | **Labels:** implementation, close, eof, state-machine

As either peer, I want a correct two-way close handshake and deterministic EOF handling so that terminal state, error scope, writes, and notifications occur exactly once.

**Acceptance criteria:**
- Valid local close and inbound close sequences implement the RFC 6455 two-way handshake, echo/acknowledgment rules, write-flush requirements, legal codes, optional strict UTF-8 reason, and deterministic Open-to-Closing-to-Closed transitions.
- Forbidden/reserved/out-of-range codes, one-byte payloads, invalid/truncated UTF-8 reasons, fragmented/oversized close frames, duplicate closes, application data after closing, and partial close EOF produce stable typed outcomes.
- EOF before open, after local close, after remote close, with pending writes, and during incomplete framing/fragmentation maps to the declared normal or abnormal close semantics without duplicate terminal callbacks/events.
- Autobahn category 7 plus Java/Rust differential, property, fuzz, runtime, and bounded transition evidence cover all declared paths and arbitrary chunking; the abstract temporal model remains separately labeled proved-model if executed.
- Seeded wrong-code, missing-ack, data-after-close, duplicate-notification, premature-closed, and stale-fragment mutants are killed and retained.

### US-017 — Drive bounded concurrent commands through one owner
**Priority:** 2 | **Passes:** true | **Depends on:** US-009, US-012, US-013, US-014, US-015, US-016 | **Labels:** implementation, concurrency, backpressure, safe-rust

As a multithreaded caller, I want bounded send and close commands serialized by one connection owner so that backpressure, flush order, shutdown, and terminal delivery are race-safe without shared mutable protocol state.

**Acceptance criteria:**
- Multiple producers may enqueue bounded SendText, SendBinary, Ping, and Close commands while exactly one owner applies commands and inbound bytes to ConnectionCore and drains ordered writes/events.
- Queue-full, receiver-drop, adapter shutdown, pending-write backpressure, peer close, local close, simultaneous close, EOF, and callback/event delivery have explicit typed behavior and cannot deadlock, leak, reorder committed writes, or deliver terminal state twice.
- Bounded schedule exploration fixes tasks, commands, inbound actions, flushes, shutdowns, preemptions, and fairness assumptions and retains minimized schedules for every failure; it remains systematic concurrency evidence, not proof.
- Actual native-thread stress/race checks run separately from the modeled schedules across both blocking platforms with repeat counts and flake reconciliation; missing race tooling blocks the named runtime claim.
- Conformance and differential adapters invoke this same driver and core; seeded lock-sharing, lost-command, queue-bypass, write-reorder, close-race, and duplicate-delivery defects are killed.

### US-018 — Add thin blocking TCP client and server adapters
**Priority:** 2 | **Passes:** true | **Depends on:** US-010, US-011, US-012, US-013, US-014, US-015, US-016, US-017 | **Labels:** implementation, tcp, adapter, autobahn

As a conformance runner, I want minimal TCP adapters around the exact core and owner driver so that Autobahn can exercise shipped behavior without moving protocol logic into networking code.

**Acceptance criteria:**
- The client and server adapters own only socket accept/connect, partial read/write, write flushing, bounded I/O buffers, explicit timeout/EOF commands, process lifecycle, and report/testee routing; handshake, framing, limits, and close semantics remain in ConnectionCore.
- Adapters support loopback WS only, one connection owner per socket, bounded connection/command/write resources, clean shutdown, failed-connect, partial I/O, peer loss, slow reader/writer, and interrupted system-call behavior on macOS arm64 and Linux x86_64.
- A linkage test proves the adapters call the exact shipped core/driver symbols and a seeded adapter-side parser or protocol branch fails the architecture gate.
- Loopback client-to-Rust-server, Rust-client-to-loopback-server, Java/Rust cross-peer, echo, control, close, loss, and backpressure integrations reconcile semantic events and wire writes.
- No TLS, proxy, reconnect, Android, async-runtime, extension, compression, or general public client/server API is added.

### US-019 — Pass both pinned Autobahn conformance modes
**Priority:** 2 | **Passes:** true | **Depends on:** US-018 | **Labels:** conformance, autobahn, client, server

As an external conformance reviewer, I want the Rust client and server tested by the exact promoted Autobahn suite so that wire behavior is independently exercised in both roles.

**Acceptance criteria:**
- The promoted v25.10.1 image runs by manifest digest on native Linux x86_64 with fixed config/report bytes, loopback-only networking, bounded resources, and clean per-run workspaces; latest is canary-only.
- A statically expanded immutable case manifest enumerates every selected case in 1.*, 2.*, 3.*, 4.*, 5.*, 6.*, 7.*, and 10.* and records 9.*, 12.*, and 13.* as declared nonselected categories, never test skips.
- Fuzzing-server mode tests the Rust client and fuzzing-client mode tests the Rust server; every in-scope case is strict-pass and expected, selected, executed, passed, failed, non-strict, informational, skipped, filtered, timed-out, and missing counts reconcile exactly.
- The same manifest proves the pinned Java baseline, empty/stub Rust negative control, and planted protocol mutants discriminate as expected; a stale historical upstream report cannot satisfy any gate.
- Raw and normalized reports, suite/config/image/source digests, process identities, resource limits, logs, and replay commands enter the evidence DAG without protected data.
