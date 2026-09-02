// Package normcollide turns the differential's NORMALIZATION SURFACE into a
// checkable census, and decides normalization-collision candidates BY
// CONSTRUCTION rather than by argument.
//
// A normalization collision is when two genuinely different wire behaviours
// map onto the same normalized observation, so the differential reads parity
// where the wire differs. Three were known before this package, and the
// project's own record says all three were found by accident:
//
//   - DIV-02 (server leaves TCP open) — registered in internal/ac5class as
//     "DIV-02-server-leaves-tcp-open"; the vocabulary has no transport
//     dimension, so it had to be measured out of band from Autobahn bytes.
//   - The US-013 AC5 event-order seed — moves nothing because Events[] and
//     Transitions[] are separate arrays (internal/lab/oracle.go:315, :325),
//     so cross-array ordering is unrepresentable.
//   - Java-quirk emulation — registered as
//     "AC5-JQ-STRUCTURAL-no-java-vs-rust-signal"; emulating Java makes Java
//     agree, so a Java-versus-Rust comparison can never see it.
//
// Three found by accident means the population was unknown. This package
// enumerates the surface and runs seeds against it.
//
// # What a decision here is worth
//
// Every probe is decided by EXECUTING the real harness on two seed requests
// and running the REAL comparator (diffregress.CompareResponses) over the two
// answers. Nothing is predicted. A probe is:
//
//   - CONFIRMED when the collision pair produces no behavioural difference at
//     all — every path the comparator can report is either absent or one of
//     the three identity fields — AND the pair is proved genuinely different,
//     either by a WITNESS pair (the same distinction, carried into a
//     projection that does represent it, where the comparator DOES move) or
//     by a WIRE witness (the seeds' own input octets differ, for distinctions
//     no projection can represent at all).
//   - REFUTED when the comparator moves. The surface represents the
//     distinction; the candidate was a hypothesis and is now closed.
//
// A candidate that has been reasoned about but not run is not in Probes() at
// all. It lives in Candidates(), is labelled HYPOTHESIS, and is never counted
// as a finding.
//
// # The limit of this enumeration
//
// Enumerating a surface is not a proof the enumeration is complete. This
// package reads the four response projections in
// rust/ws-oracle-harness/src/response.rs, the handshake projection in
// handshake_adapter.rs, and the two scorers (internal/corpora
// EvaluateOracleResponse and evaluateHandshakeLiveResponse). A distinction
// that none of those five sites mentions cannot be found by reading them —
// DIV-02 is exactly that case, and it is in this catalog only because a
// person had already found it. The claim this package supports is BOUNDED,
// not complete: it is "these named distinctions are erased", never "these are
// all the distinctions that are erased".
package normcollide

// Projection names one response-construction site and records exactly which
// top-level keys it emits. The KeysEmitted lists are not authored: the
// document recomputes them from the real responses the probes produce, and
// Verify refuses if a recomputed list disagrees with the committed one.
type Projection struct {
	// ID is the stable name of the projection.
	ID string `json:"id"`
	// Site is the source location that builds it.
	Site string `json:"site"`
	// Trigger says when this projection is the one that answers.
	Trigger string `json:"trigger"`
	// Drops names the observation content this projection does not emit,
	// relative to the fullest projection on its surface.
	Drops []string `json:"drops"`
	// Scorer names the function that actually scores rows of this shape in
	// the headline number, and Scores lists exactly what it compares.
	Scorer string `json:"scorer"`
	// Scores lists the fields the scorer compares for this projection.
	Scores []string `json:"scores"`
}

// Projections is the enumerated normalization surface: every response shape
// the two protocols can produce. Adding a fifth projection to the harness
// without adding it here fails TestProjectionsCoverEveryObservedKeySet,
// because that test partitions the real observed key-sets across this list.
func Projections() []Projection {
	return []Projection{
		{
			ID:      "behaviour.ok",
			Site:    "rust/ws-oracle-harness/src/response.rs ok_response",
			Trigger: "the scenario ran to completion",
			Drops: []string{
				"cross-array ordering between events[], frames[] and transitions[]",
				"frame mask keys (quirk Q28: payloads are recorded unmasked)",
				"every transport-layer fact: socket lifecycle, TCP FIN/RST, flush boundaries, timing",
			},
			Scorer: "internal/corpora.EvaluateOracleResponse (ok branch)",
			Scores: []string{
				"request_id", "request_digest", "protocol", "version", "outcome",
				"close", "counts", "events", "final_state", "frames",
				"initial_state", "role", "transitions",
			},
		},
		{
			ID:      "behaviour.failure",
			Site:    "rust/ws-oracle-harness/src/response.rs failure_response",
			Trigger: "the scenario failed part-way (mirrors OracleEngine.failure)",
			Drops: []string{
				"events[] — the entire semantic event stream",
				"frames[] — the entire frame record stream",
				"transitions[] — the entire state-transition stream",
				"close — the governing close detail",
				"role and initial_state (request echoes, recoverable from request_digest)",
			},
			Scorer: "internal/corpora.EvaluateOracleResponse (error branch)",
			Scores: []string{
				"request_id", "request_digest", "protocol", "version", "outcome",
				"error.code", "error.close_code", "final_state", "counts",
			},
		},
		{
			ID:      "behaviour.output_limit",
			Site:    "rust/ws-oracle-harness/src/response.rs output_limit_response",
			Trigger: "the canonicalized response exceeds the request's max_output_bytes",
			Drops: []string{
				"events[], frames[], transitions[], close",
				"counts — every counter",
				"final_state",
				"runtime — the responder's own identity",
				"error.close_code",
			},
			Scorer: "internal/corpora.EvaluateOracleResponse (error branch)",
			Scores: []string{
				"request_id", "request_digest", "protocol", "version", "outcome",
				"error.code",
			},
		},
		{
			ID:      "behaviour.envelope_error",
			Site:    "rust/ws-oracle-harness/src/response.rs envelope_error_response",
			Trigger: "the line never reached scenario execution (mirrors OracleMain.error)",
			Drops: []string{
				"request_id is literally null — there is no id binding",
				"request_digest — there is no request binding at all",
				"counts, final_state, runtime and every observation stream",
			},
			Scorer: "NONE — diffregress.LoadTranscript REFUSES a null request_id, " +
				"so a transcript containing one of these cannot be compared at all",
			Scores: []string{},
		},
		{
			ID:      "handshake.judged",
			Site:    "rust/ws-oracle-harness/src/handshake_adapter.rs respond",
			Trigger: "any handshake-protocol line",
			Drops: []string{
				"the entire HTTP head — status line, header set, header order, Date",
				"subprotocol negotiation (Sec-WebSocket-Protocol)",
				"extension negotiation (Sec-WebSocket-Extensions)",
				"request path and Host",
				"how many bytes an `incomplete` consumed, and in what state it stopped",
				"the Sec-WebSocket-Key on any rejected case",
			},
			Scorer: "internal/corpora.evaluateHandshakeLiveResponse",
			Scores: []string{
				"case_id", "request_digest", "protocol", "version", "runtime",
				"java_observable", "reject_channel", "close_code", "sec_websocket_accept",
			},
		},
	}
}

// IdentityFields are the only response members a collision comparison strips.
// They bind WHICH request was asked, not WHAT the connection did, so two
// different requests necessarily differ there and a collision claim that did
// not strip them could never be made. Stripping anything else would weaken
// the check, and TestIdentityFieldsAreExactlyThree pins the list.
func IdentityFields() []string {
	return []string{"case_id", "request_digest", "request_id"}
}
