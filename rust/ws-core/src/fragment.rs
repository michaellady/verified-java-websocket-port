//! Fragmentation plane placeholder (US-014).
//!
//! Reserved for bounded fragment reassembly mirroring
//! `org.java_websocket.framing.ContinuousFrame` handling (migration map
//! planned identity `ws_core::fragment::ContinuousFrame`). Contract-pinned
//! semantics for the implementing story: cumulative fragment totals are
//! checked only at starts and fins (`checkBufferLimit`, quirk Q23) — a
//! non-fin continuation that overflows trips the adapter's own accounting
//! (`BUFFER_LIMIT_EXCEEDED`, no close code) while a fin-time overflow trips
//! close code 1009; the port additionally enforces the reassembly cap on
//! EVERY fragment append (the planned strengthening
//! note.fragmentation.per-append-buffer-cap, a behavior-delta-ledger
//! obligation for US-012/US-014, never a Java parity claim). This module
//! intentionally exports nothing yet: no reassembly exists, and no
//! fragmentation behavior is claimed by US-009.
