package deltaledger

// protocolRejectionStateDefinitions ledger the CLASS that the cross-plane
// defect audit found one instance of.
//
// The audit (drafts/codex-us020-defect-crosscheck.md section 8) reported a
// single divergence: us005.pub.0005 leaves final_state OPEN after a
// reserved-bit rejection, where an RFC-strict reading fails the connection.
// Sequence 44 ledgers that instance. Sweeping the committed public corpus for
// the same CAUSE — an inbound frame decode that the pinned Java decoder rejects
// with an InvalidDataException, where the recorded ready state nevertheless
// stays open — finds that it is not one scenario but EIGHTEEN, spanning ten
// families, and every one of them has the same single cause.
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
// calls close(e) at WebSocketImpl.java:408, is never reached.
//
// This record therefore states something the audit's framing could not: the
// divergence is NOT a clean "RFC says closed, Java says open" split. Shipped
// Java's own library path DOES close. What stays open is the adapter path, and
// the adapter is what the corpus measures. Anyone reasoning about this as
// RFC-versus-Java will draw the wrong conclusion about which reading is
// Java-faithful, because both readings are.
//
// FOUR ERRORS IN THE FIRST VERSION OF THIS RECORD, all inside hashed digest
// preimages and all corrected here after review 01a0495e (BLOCKING 10):
//
//   - Its JavaObservation ended "through the shipped library the connection
//     DOES leave OPEN; through the adapter it does not", which is the exact
//     reverse of what the same record's JavaValue, its rationale and the pinned
//     source all say. The library path CLOSES; the adapter path is the one that
//     stays open.
//   - Its rationale said an RFC-strict rejection "leaves OPEN". RFC-strict is
//     precisely the reading under which it does NOT stay open; that is what
//     makes it a divergence at all.
//   - It cited the reserved-bit record as sequence 45. It is sequence 44;
//     sequence 45 is the first of the three superseding budget corrections.
//   - It cited WebSocketImpl.java:404-407 for close(e). Line 404 is the
//     LimitExceededException arm's close; the InvalidDataException arm spans
//     405-408 and its close(e) is line 408.
//
// A fifth correction is a consequence of BLOCKING 4 rather than of BLOCKING 10:
// the class was previously swept by the RESULT SHAPE `close_code in
// {1002,1007,1009}`, which enrolled us005.pub.0000 — a locally initiated
// send_close(999) with zero inbound bytes, whose RFC behaviour REMAINS OPEN
// because no Close frame was ever sent, and which sequence 35 already ledgers
// correctly. The class is now swept by CAUSE and is eighteen scenarios, not
// nineteen. See InProtocolRejectionClass in evidence_census.go.
//
// Appended last so the committed 47-record prefix is unchanged.
func protocolRejectionStateDefinitions() []Definition {
	return []Definition{
		{
			Subject: "org.java-websocket.oracle-adapter.protocol-rejection-readystate-class",
			RFCRefs: []string{
				"rfc6455#section-5.2",
				"rfc6455#section-7.1.7",
				"rfc6455#section-7.4.1",
				"rfc6455#section-8.1",
			},
			RFCExpectation: "RFC 6455 section 7.1.7 defines _Fail the WebSocket Connection_: where certain algorithms " +
				"and specifications require it, the endpoint closes the WebSocket connection, SHOULD send a Close " +
				"frame with an appropriate status code where the connection is established, and MUST NOT continue to " +
				"process data from the remote endpoint afterwards. Section 5.2 requires an endpoint that receives a " +
				"nonzero RSV bit with no negotiated extension defining it to fail the connection (status 1002), and " +
				"section 8.1 requires an endpoint that receives a text message not encoded in valid UTF-8 to fail the " +
				"connection (status 1007). Section 7.4.1 defines 1009 for a message too big to process. NOTE ON WHAT " +
				"SECTION 10.4 DOES AND DOES NOT SAY, stated because an earlier version of this record misread it: " +
				"10.4 does not itself direct an endpoint to fail a connection. Its text is: \"" +
				rfc6455Section104Verbatim + "\" It obliges an implementation with such limitations to protect itself " +
				"and recommends imposing frame and message limits; the close code for the over-limit case comes from " +
				"section 7.4.1, and the failure obligation from 7.1.7. Under an RFC-strict reading, none of these " +
				"eighteen recorded inbound-decode rejections leaves the endpoint in the OPEN ready state.",
			RFCValue: "closed: every inbound protocol-level decode rejection takes the endpoint out of OPEN",
			JavaRef:  "org.java_websocket.WebSocketImpl:decodeFrames",
			JavaObservation: "This is a CLASS record. The committed public corpus contains eighteen scenarios whose " +
				"recorded error code is JAVA_INVALID_DATA — the decoder's typed rejection — raised while decoding " +
				"INBOUND bytes (counts.input_bytes > 0), and whose recorded final_state is nevertheless open: " +
				"us005.pub.0005, us005.pub.0019, us005.pub.0020, us005.pub.0029, us005.pub.0031, us005.pub.0033, " +
				"us005.pub.0036, us005.pub.0039, us005.pub.0041, us005.pub.0042, us005.pub.0052, us005.pub.0056, " +
				"us005.pub.0057, us005.pub.0058, us005.pub.0059, us005.pub.0065, us005.pub.0066 and us005.pub.0067, " +
				"across the families rsv-bit, close-code-invalid-wire, control-nonfin, buffer-limit-frame, " +
				"bad-opcode, unexpected-continuation, data-during-fragment, fragment-restart, invalid-utf8-text and " +
				"control-oversize (fifteen at close code 1002, two at 1007, one at 1009). NOT IN THE CLASS, and why: " +
				"us005.pub.0000 is a locally initiated send_close(999) with input_bytes 0 and consumed_bytes 0, so no " +
				"inbound byte was ever decoded and RFC 6455 section 7.1.7 does not require closing — an invalid local " +
				"API call is not a provision requiring _Fail the WebSocket Connection_. It is ledgered separately and " +
				"correctly at sequence 35. Every member of the class is live-confirmed: the recorded expectation and " +
				"the live pinned-Java transcript agree at /final_state on all eighteen " +
				"(protected/us005-corpora/live/public/transcript.jsonl; 74/74 reconciled). THE SINGLE CAUSE, read in " +
				"the pinned trees: the oracle adapter constructs a WebSocketImpl " +
				"(java-oracle/src/main/java/OracleEngine.java line 307) but uses it at exactly ONE call site — as the " +
				"listener passed to draft.processFrame (OracleEngine.java:387). It never invokes " +
				"WebSocketImpl.decodeFrames and never invokes WebSocketImpl.close. Inbound bytes are handed straight " +
				"to draft.translateFrame (OracleEngine.java:343); local actions construct and validate frames directly " +
				"(sendClose at OracleEngine.java:461-475). The InvalidDataException each rejection raises therefore " +
				"propagates to the adapter's top-level catch (OracleEngine.java:95-97), which records the code and the " +
				"close code, and the close ladder in WebSocketImpl.decodeFrames (WebSocketImpl.java:391-419) — whose " +
				"InvalidDataException arm at WebSocketImpl.java:405-408 calls close(e) at line 408 — is never " +
				"reached. TWO ENTRY POINTS, TWO ANSWERS: through the shipped library the connection LEAVES the OPEN " +
				"ready state, because decodeFrames closes it; through the adapter it STAYS OPEN, and the adapter is " +
				"what the corpus measures.",
			JavaValue: "entry-point-dependent: WebSocketImpl.decodeFrames closes on the caught InvalidDataException " +
				"(close(e) at WebSocketImpl.java:408), while the adapter never routes through it and the " +
				"live-recorded ready state stays open on all eighteen scenarios",
			AutobahnRefs: []string{"autobahn-v25.10.1:3.1", "autobahn-v25.10.1:5.1", "autobahn-v25.10.1:6.1.1"},
			Rationale: "DIVERGENCE (inbound protocol-decode rejection, resulting ReadyState — CLASS record): under an " +
				"RFC-strict reading every one of these rejections fails the WebSocket connection and therefore does " +
				"NOT leave the endpoint OPEN; the port stays OPEN because that is what the live pinned Java oracle " +
				"records, on all eighteen affected public-corpus scenarios. SCOPE AND RELATION TO THE " +
				"SINGLE-INSTANCE RECORDS: sequence 44 ledgers the reserved-bit instance (us005.pub.0005); this record " +
				"covers the remaining seventeen and names the mechanism they all share. Sequence 35 ledgers " +
				"us005.pub.0000, which is a DIFFERENT proposition and deliberately NOT a member of this class: it is " +
				"a locally initiated close with no inbound decode, so no RFC provision requires failing the " +
				"connection there. That distinction is the substance of review 01a0495e BLOCKING 4, which found the " +
				"earlier close-code-shaped sweep enrolling it. This record exists because the cross-plane audit found " +
				"ONE instance by hand and no gate of ours would have found the other seventeen — the census at " +
				"evidence/us005-public-rfc-divergence-census.json now enumerates the class mechanically from the " +
				"committed corpus BY CAUSE, and internal/deltaledger.VerifyIntegrity refuses unless every row names a " +
				"ledger record that actually discusses that scenario. THE FRAMING MATTERS AND IS DELIBERATELY NOT " +
				"FLATTENED: this is not a clean RFC-versus-Java split. Shipped Java's own WebSocketImpl.decodeFrames " +
				"DOES close on these rejections; the adapter path simply never reaches it. Both readings are " +
				"Java-faithful — they are faithful to DIFFERENT ENTRY POINTS of the same pinned runtime — and any " +
				"review that treats 'Java says open' as the whole story will mis-rank the evidence. WS_CORE SITE: " +
				"rust/ws-core/src/framing.rs and rust/ws-core/src/connection.rs produce the typed rejection without a " +
				"state transition; pinned by " +
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
