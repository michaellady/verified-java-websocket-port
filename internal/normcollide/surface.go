// Package normcollide turns the differential's NORMALIZATION SURFACE into a
// checkable census, and decides normalization-collision candidates BY
// CONSTRUCTION rather than by argument.
//
// A normalization collision is when two genuinely different wire behaviours
// map onto the same normalized observation, so the differential reads parity
// where the wire differs. Three were known before this package, and the
// project's own record says all three were found by accident:
//
//   - DIV-02 (server leaves TCP open) — registered in internal/defectclass as
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
// # Why a two-REQUEST collision bounds a two-ARM differential
//
// The obvious objection: the differential never compares row A against row B.
// It compares O_java(R) against O_rust(R) for one request R. So what does a
// collision between two different requests prove?
//
// It proves the projection O is blind to a distinction, and O is the same
// function on both arms. Every probe here is built so its two requests differ
// ONLY in the content whose behavioural effect is at issue — the text payload
// (NC-01), the frame octets (NC-03, NC-04), the handshake octets (NC-07..09) —
// with limits, role and initial_state held equal. So when the two answers are
// equal modulo identity, what has been shown is O(b1) == O(b2) for two
// behaviours b1 != b2 that the SAME projection maps together.
//
// The differential consequence follows directly: if the port, on request A,
// produced b2 where Java produced b1, the two arms' rows for A would be equal
// and the differential would read parity. NC-01 makes that concrete — a port
// that emitted the wrong outbound payload before failing is invisible. NC-04
// makes it concrete on a bit — a port that mis-read the FIN flag of a frame it
// then rejected is invisible.
//
// What this does NOT establish is that any such port defect exists. A
// collision bounds what the differential could detect; it is not itself a
// defect report, and nothing in this package claims one.
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
				"every distinction WITHIN one draft-API stage: shipped Java's own " +
					"InvalidHandshakeException messages separate a non-GET method from a bad " +
					"HTTP version from a header line with no colon, but those are " +
					"implementation strings the differential classifies non-semantic " +
					"(diffregress DetailField), and reproducing them would be Java-quirk " +
					"emulation, which by construction produces no Java-versus-Rust signal",
			},
			Scorer: "internal/corpora.evaluateHandshakeLiveResponse",
			Scores: []string{
				"case_id", "request_digest", "protocol", "version", "runtime",
				"java_observable", "reject_channel", "reject_stage", "close_code",
				"sec_websocket_accept",
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
