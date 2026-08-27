//! Server-side opening handshake placeholder (US-011).
//!
//! Reserved for the migration map's planned `ws_core::handshake::server::*`
//! identities (ServerHandshake and builders) and the Java-faithful
//! acceptance predicate (quirks Q1-Q8: version==13 via trimmed integer
//! parse, non-empty key only, no Host/Upgrade/Connection examination, exact-
//! CRLF line termination, `"; "` duplicate-header joining, one collapsed
//! rejection observable). The accept-value derivation
//! (`generate_accept_key`, SHA-1 over the trimmed key + RFC magic,
//! Draft_6455.java:832-841) is planned as
//! `ws_core::framing::Draft6455::generate_accept_key`
//! (target.formal.handshake.accept-derivation). This module intentionally
//! exports nothing yet: no handshake behavior is claimed by US-009.
