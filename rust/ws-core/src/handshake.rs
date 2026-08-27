//! Opening-handshake plane (US-010 client, US-011 server) — reserved entry
//! points only.
//!
//! US-009 reserves the migration map's planned namespaces
//! `ws_core::handshake::client` and `ws_core::handshake::server`; it claims
//! no handshake behavior. The handshake tier speaks its own oracle protocol
//! (`java-websocket-handshake-oracle`,
//! `schemas/corpus-handshake-case-1.0.0.schema.json`), separate from the
//! behavior corpora.
//!
//! Contract-pinned semantics for the implementing stories (quirks Q1-Q9;
//! `docs/us005-handshake-verdict-mapping.md`, verified live against the
//! pinned jar): the server-side acceptance predicate is Java's, not RFC
//! 6455's — accept iff `Sec-WebSocket-Version` parses (after trim) to 13 and
//! `Sec-WebSocket-Key` is present and non-empty; every server-side rejection
//! collapses to one observable (HTTP 404 error body + close 1002); the
//! client side is the strict side (`basicAccept`, Draft.java:188-191). Java
//! has NO handshake byte/header limits (WebSocketImpl.java:370-387 grows
//! unboundedly); the port enforces the three configured handshake limits as
//! a JAVA_FAITHFUL_PLUS_SAFE strengthening, ledger-routed once baselines
//! exist.

pub mod client;
pub mod server;
