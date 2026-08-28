package deltaledger

// protocolRejectionStateDefinitions ledger the CLASS that the cross-plane
// defect audit found one instance of.
//
// The audit (drafts/codex-us020-defect-crosscheck.md section 8) reported a
// single divergence: us005.pub.0005 leaves final_state OPEN after a
// reserved-bit rejection, where an RFC-strict reading fails the connection.
// Sequence 45 ledgers that instance. Sweeping the committed public corpus for
// the same predicate — outcome error, a protocol close code (1002/1007/1009),
// final_state open — finds that it is not one scenario but NINETEEN, spanning
// eleven families, and every one of them has the same single cause.
//
// THE CAUSE, verified in the pinned trees rather than inferred. The oracle
// adapter constructs a WebSocketImpl (java-oracle/src/main/java/OracleEngine.java
// line 307) but uses it at exactly ONE call site: as the listener argument to
// draft.processFrame (OracleEngine.java:387). It never calls
// WebSocketImpl.decodeFrames and never calls WebSocketImpl.close. Inbound bytes
// go straight to draft.translateFrame (OracleEngine.java:343) and local actions
// build and validate frames directly (for example sendClose at
// OracleEngine.java:461-475). So the InvalidDataException that every one of
// these rejections raises propagates to the adapter's top-level catch
// (OracleEngine.java:95-97), which records the error and the close code — and
// the close ladder in WebSocketImpl.decodeFrames, whose InvalidDataException arm
// calls close(e) at WebSocketImpl.java:404-407, is never reached.
//
// This record therefore states something the audit's framing could not: the
// divergence is NOT a clean "RFC says closed, Java says open" split. Shipped
// Java's own library path DOES close. What stays open is the adapter path, and
// the adapter is what the corpus measures. Anyone reasoning about this as
// RFC-versus-Java will draw the wrong conclusion about which reading is
// Java-faithful, because both readings are.
//
// Appended last so the committed 45-record prefix is unchanged.
func protocolRejectionStateDefinitions() []Definition {
	return []Definition{
		{
			Subject: "org.java-websocket.oracle-adapter.protocol-rejection-readystate-class",
			RFCRefs: []string{
				"rfc6455#section-5.2",
				"rfc6455#section-7.1.7",
				"rfc6455#section-8.1",
				"rfc6455#section-10.4",
			},
			RFCExpectation: "RFC 6455 section 7.1.7 defines _Fail the WebSocket Connection_: the endpoint sends a Close " +
				"frame with an appropriate status code where the connection is open, then closes, and MUST NOT process " +
				"further data. Sections 5.2 (framing and reserved-bit errors, 1002), 8.1 (invalid UTF-8 in a text " +
				"message, 1007) and 10.4 (implementation limits, 1009) each direct an endpoint to fail the connection " +
				"on the corresponding error. Under an RFC-strict reading, none of these nineteen recorded rejections " +
				"leaves the endpoint in the OPEN ready state.",
			RFCValue: "closed: every protocol-level rejection takes the endpoint out of OPEN",
			JavaRef:  "org.java_websocket.WebSocketImpl:decodeFrames",
			JavaObservation: "This is a CLASS record: the committed public corpus contains nineteen scenarios whose " +
				"recorded outcome is error with a protocol close code and whose recorded final_state is open — " +
				"us005.pub.0000, 0005, 0019, 0020, 0029, 0031, 0033, 0036, 0039, 0041, 0042, 0052, 0056, 0057, 0058, " +
				"0059, 0065, 0066 and 0067, across the families send-close-invalid-code, rsv-bit, " +
				"close-code-invalid-wire, control-nonfin, buffer-limit-frame, bad-opcode, unexpected-continuation, " +
				"data-during-fragment, fragment-restart, invalid-utf8-text and control-oversize (sixteen at 1002, two " +
				"at 1007, one at 1009). Every one is live-confirmed: the recorded expectation and the live pinned-Java " +
				"transcript agree at /final_state on all nineteen " +
				"(protected/us005-corpora/live/public/transcript.jsonl; 74/74 reconciled). THE SINGLE CAUSE, read in " +
				"the pinned trees: the oracle adapter constructs a WebSocketImpl " +
				"(java-oracle/src/main/java/OracleEngine.java line 307) but uses it at exactly ONE call site — as the " +
				"listener passed to draft.processFrame (OracleEngine.java:387). It never invokes " +
				"WebSocketImpl.decodeFrames and never invokes WebSocketImpl.close. Inbound bytes are handed straight " +
				"to draft.translateFrame (OracleEngine.java:343); local actions construct and validate frames directly " +
				"(sendClose at OracleEngine.java:461-475). The InvalidDataException each rejection raises therefore " +
				"propagates to the adapter's top-level catch (OracleEngine.java:95-97), which records the code and the " +
				"close code, and the close ladder in WebSocketImpl.decodeFrames — whose InvalidDataException arm calls " +
				"close(e) at WebSocketImpl.java:404-407 — is never reached. TWO ENTRY POINTS, TWO ANSWERS: through the " +
				"shipped library the connection DOES leave OPEN; through the adapter it does not, and the adapter is " +
				"what the corpus measures.",
			JavaValue: "entry-point-dependent: WebSocketImpl.decodeFrames closes on the caught InvalidDataException " +
				"(WebSocketImpl.java:404-407), while the adapter never routes through it and the live-recorded ready " +
				"state stays open on all nineteen scenarios",
			AutobahnRefs: []string{"autobahn-v25.10.1:3.1", "autobahn-v25.10.1:5.1", "autobahn-v25.10.1:6.1.1"},
			Rationale: "DIVERGENCE (protocol rejection, resulting ReadyState — CLASS record): under an RFC-strict " +
				"reading every protocol-level rejection fails the connection and leaves OPEN; the port stays OPEN " +
				"because that is what the live pinned Java oracle records, on all nineteen affected public-corpus " +
				"scenarios. SCOPE AND RELATION TO THE SINGLE-INSTANCE RECORDS: sequence 45 ledgers the reserved-bit " +
				"instance (us005.pub.0005) and sequence 35 the rejected-local-close instance (us005.pub.0000); this " +
				"record covers the remaining seventeen and names the mechanism they all share. It exists because the " +
				"cross-plane audit found ONE instance by hand and no gate of ours would have found the other eighteen " +
				"— the new census at evidence/us005-public-rfc-divergence-census.json now enumerates the class " +
				"mechanically from the committed corpus and the live transcript, and refuses unless every row has a " +
				"ledger record. THE FRAMING MATTERS AND IS DELIBERATELY NOT FLATTENED: this is not a clean " +
				"RFC-versus-Java split. Shipped Java's own WebSocketImpl.decodeFrames DOES close on these rejections; " +
				"the adapter path simply never reaches it. Both readings are Java-faithful — they are faithful to " +
				"DIFFERENT ENTRY POINTS of the same pinned runtime — and any review that treats 'Java says open' as " +
				"the whole story will mis-rank the evidence. WS_CORE SITE: rust/ws-core/src/framing.rs and " +
				"rust/ws-core/src/connection.rs produce the typed rejection without a state transition; pinned by " +
				"rust/ws-core/tests/frame_codec.rs::reserved_bits_reject_1002_only_after_the_full_frame and " +
				"rust/ws-core/tests/close_eof.rs::send_close_invalid_code_rejects_without_a_frame. SAFETY: staying " +
				"OPEN after a refused frame is not permissive at the wire — the frame is rejected, nothing is " +
				"delivered, no byte is written, and consumption stays bounded by the control-payload and configured " +
				"frame-size gates under forbid(unsafe_code). An embedding layer that wants RFC 7.1.7 failure semantics " +
				"drives the close from the returned typed failure, exactly as the shipped library's own decodeFrames " +
				"does. DISPOSITION NOTE: 'unresolved' is the frozen 1.0.0 vocabulary's only retained-divergence term; " +
				"the divergence is deliberately retained on live evidence, not left unexamined." + ownerDecision,
		},
	}
}
