//! Message plane placeholder (US-013).
//!
//! Reserved for text/binary message delivery and the incremental UTF-8
//! machinery mirroring `org.java_websocket.util.Charsetfunctions` (migration
//! map row `migration.org-java-websocket-util-charsetfunctions`; planned
//! proof-target symbols `ws_core::message::Charsetfunctions::is_valid_utf8`
//! and `ws_core::message::Charsetfunctions::string_utf8`,
//! target.formal.messages.utf8-validation-total). The two-stage truncated-
//! tail semantics are contract-pinned (quirk Q15): the translate-time
//! Hoehrmann DFA rejects only in its error state, so a payload ending in a
//! valid-but-incomplete multi-byte prefix is accepted at translate time and
//! the frame is recorded; the strict process-time decoder then rejects it
//! with close code 1007 — the two gates must stay distinct (US-013 may not
//! collapse them into one RFC-style check). This module intentionally
//! exports nothing yet: no UTF-8 validation or message delivery exists, and
//! no message behavior is claimed by US-009.
