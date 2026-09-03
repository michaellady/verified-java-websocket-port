// Package rfcneutral derives a neutral ready-state expectation for the public
// corpus from the stated rules of RFC 6455 sections 5 and 7, applied
// mechanically to each scenario's own inbound octets.
//
// # Why this package exists
//
// evidence/oracle-hierarchy/adjudication-register.json carries two BLOCKING
// findings, ORACLE-RANK-INDISTINGUISHABLE-3-4 and -3-5, which say that US-020
// AC2's rank three ("independent neutral expectations") never once differed
// from rank four or rank five where the two read different bytes. The recorded
// cause is that every one of the 74 public expectations is
// REFERENCE_MODEL_DERIVED_PENDING_ORACLE_CONFIRMATION, produced by
// internal/corpora.DeriveExpected under a reference model whose own doc comment
// says its defaults mirror pinned Java-WebSocket 1.6.0. An expectation derived
// from a Java-mirroring model is not an independent check on Java.
//
// This package is a second derivation that does not pass through that model.
// It imports nothing from internal/corpora, and the scenario struct it decodes
// into HAS NO expected FIELD, so a scenario's recorded expectation cannot reach
// a verdict here even by accident. TestDerivationIgnoresRecordedExpectation
// proves that structurally by re-deriving over a corpus whose every `expected`
// block has been replaced with a contradictory one and requiring byte-identical
// decisions.
//
// # What this package is NOT
//
// It is NOT bound to RFC 6455. The RFC text is pinned by digest in
// evidence/intake/source-pins.json and is NOT in this repository; egress to
// www.rfc-editor.org is denied from this environment. Every rule in rules.go is
// therefore a RECORDED READING of the standard written by hand, exactly as
// rank one's readings in evidence/us005-handshake-live-mapping.json and
// evidence/us005-public-rfc-divergence-census.json are. This package claims no
// more binding than rank one has. A misreading of a clause here would pass
// every gate in this repository unchanged, and Decisions carries the clause
// reference for each rule precisely so a reader with the text can check it.
//
// What it does claim, and what the register's independence probe can then
// measure, is narrower and checkable:
//
//	(a) the rules are stated once, in a table, independently of any scenario;
//	(b) they are applied uniformly by a decoder to the scenario's own octets;
//	(c) no Java artifact, and no reference-model output, is read on the way.
//
// # Abstention
//
// The package abstains rather than guessing, and every abstention names the
// reason. RFC 6455 does not define readyState -- CLOSING and CLOSED are the
// W3C WebSocket API's states, not the RFC's -- so this derivation can separate
// "the RFC requires Failing the WebSocket Connection" (section 7.1.7, which
// leaves the connection Closed) from "no such provision fired" (open), and it
// abstains wherever the answer turns on a distinction the RFC does not draw or
// on a harness limit the RFC does not state. See Rule and the AbstainRule
// constants for the closed list.
package rfcneutral
