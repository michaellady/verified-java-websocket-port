# F010 — DIV-06's fix makes the port emit exactly what US-011 AC2 forbids, and the ledger record still describes the pre-fix port
phase: criteria audit (US-010/US-011, first pass)   step: n/a   date: 2026-09-03T12:27Z

what happened: auditing US-010 and US-011 against the child PRD for the first time — they had never been audited — turned up a direct contradiction between a change I reviewed and landed today and an acceptance criterion that was in the tree the whole time.

**US-011 AC2** (`docs/prd-pack/07b-child-prd-us009-us019.md`): *"A valid request emits a deterministic 101 response with the exact Sec-WebSocket-Accept, required headers, **no Java-specific Date or Server banner**, and a normalized semantic handshake event."*

**The shipped port, after DIV-06 landed as `ddc148d`**: `rust/ws-core/src/handshake/server.rs:264` writes `\r\nDate: ` and `:268` writes `\r\nServer: TooTallNate Java-WebSocket\r\n`, and `handshake_server_response.rs` asserts all five field names in Java's TreeMap order. The port now emits precisely the two fields the criterion names as forbidden, and a test pins that it does.

**And ledger sequence 55 is stale in the same direction.** Its rationale opens *"the port's response OMITS the Server and Date fields shipped Java adds"* — the pre-fix state — while its disposition is `unresolved` / `underspecified-behavior` with an owner ruling named as the precondition. So the chain records an open question, the criterion records an answer, and the port shipped the opposite answer without either being updated.

what it cost: nothing on the wire yet — this is a laboratory and no acceptance is claimed. What it cost is trust in the landing: I reviewed DIV-06 carefully, re-read every Java citation at source, verified the anti-circularity mask was not vacuous, and traced the `Connection` echo that no sweep could have found. **I never checked the change against the acceptance criteria of the story it belongs to.**

where the deciding moment was: when the review asked "does this match shipped Java?" and never asked "does this story permit matching shipped Java here?". Java fidelity is the method, not the goal — the program's own framing is *parity without preserving Java defects*, and a vendor `Server` banner is the textbook example of a defect not to preserve. The criteria audit had covered US-017 through US-027 and never reached US-010/US-011, so the one document that would have caught it was the one nobody read.

**The two halves of DIV-06 are not the same case, and the remedy must not treat them alike.** The `Connection` echo fix (Java echoes the request's value; the port hard-coded `Upgrade`) is untouched by AC2, was the genuinely hidden divergence, and should stand. Only the `Server`/`Date` half conflicts.

evidence: `grep -n "Server:\|Date:" rust/ws-core/src/handshake/server.rs` shows both writes; `handshake_server_response.rs:109-115` pins the five names; US-011 AC2 as quoted; ledger sequence 55's rationale as quoted; DIV-06's landing commit `ddc148d`.

bin: a NEW class beside the collection. Not existence standing in for identity, and not its mirror — this is **fidelity standing in for correctness**: a change verified exhaustively against the source it imitates, and never against the specification that governs whether imitation is wanted there. Every citation in that landing was right. The question they answered was the wrong one. The portable rule: before landing a fidelity fix, read the acceptance criterion of the story that owns the surface, and check that the criterion permits the fidelity — a Java citation is not an authority for whether to follow Java.

**OWNER DECISION REQUIRED — three options, and this loop should not choose between them:**
(a) **US-011 AC2 governs**: revert the `Server`/`Date` half, keep the `Connection` echo, and supersede ledger sequence 55 with a record whose disposition is `intentional-correction` — the port deliberately declines a Java banner.
(b) **The adoption governs**: amend US-011 AC2, and supersede sequence 55 with `adopt-java` / `java-quirk` plus a rationale for why a vendor banner is worth adopting.
(c) **Split**: keep `Date` (arguably an HTTP-conventional field) and drop the `Server` banner, with the ledger recording each separately.
Whichever is chosen, sequence 55's rationale is stale as written and needs superseding — it describes a port that no longer exists, which is the same defect the DIV-05 continuation found in sequence 34 today.
