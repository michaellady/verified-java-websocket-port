//! Control-frame behavior map (US-015).
//!
//! Ping/pong behavior deliberately lives beside the state gates in
//! [`crate::connection::ConnectionCore`] rather than in a separate control
//! machine, because in the pinned Java runtime the control arms are pure
//! dispatch inside `processInbound` / `actionStep` (reference model
//! `internal/corpora/derive.go`) — there is no control state to own. This
//! module documents the sites and their quirks; it exports nothing by
//! design:
//!
//! - **Inbound delivery** (`ConnectionCore::process_inbound` ping/pong
//!   arms, derive.go:671-678): a validated ping or pong records its frame
//!   and emits one [`crate::event::SemanticEventKind::Ping`] /
//!   [`crate::event::SemanticEventKind::Pong`] event with the exact decoded
//!   payload. NO automatic pong exists in the core (quirk Q18): the
//!   reference model's observable space never contains one, so auto-pong is
//!   adapter policy above the core. Neither arm touches the fragment
//!   accumulator — controls interleave transparently (US-015 AC2).
//! - **Validity** (translate time, [`crate::framing::Draft6455`]): control
//!   frames must be fin (post-payload 1002) and their payloads at most 125
//!   bytes, with extended-length markers rejected at the 2-byte header site
//!   (derive.go:403-407) — all landed with US-012.
//! - **Send path** (`ConnectionCore::handle_command`
//!   `SendPing`/`SendPong`, derive.go actionStep:861-877): requires the
//!   open state (Q26), then emits one fin control frame with NO
//!   payload-size check (quirk Q17: `Execution.sendControl` never checks —
//!   `ControlFrame.isValid` looks only at fin and reserved bits — so the
//!   pinned runtime sends oversized control payloads successfully; the
//!   Codex encoder's >125 preflight rejection was deliberately not
//!   adopted).
//!
//! Borrow attribution: the US-015 slice was adapted from the Codex plane
//! (codex-import 8f18f91) — its 16 `fuzz-seeds/us015` regression seeds are
//! adopted byte-verbatim; its `AutomaticPongPolicy` / batch-planning /
//! caller-supplied-mask design was NOT adopted (Java-fidelity corrections,
//! see `tests/ping_pong.rs`).
