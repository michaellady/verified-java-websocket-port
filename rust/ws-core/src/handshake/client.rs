//! Client-side opening handshake placeholder (US-010).
//!
//! Reserved for the migration map's planned `ws_core::handshake::client::*`
//! identities (ClientHandshake, HandshakeState, the Base64 helper mirroring
//! `org.java_websocket.util.Base64`, and the strict `basicAccept` predicate
//! — quirk Q9: `Upgrade: websocket` case-insensitive, `Connection`
//! containing `upgrade`, `Sec-WebSocket-Accept` literally equal to the
//! generated final key). This module intentionally exports nothing yet: no
//! handshake parsing, validation, or response generation exists, and no
//! handshake behavior is claimed by US-009.
