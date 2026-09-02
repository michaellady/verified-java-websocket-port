package deltaledger

// layerSplitDefinitions is the single record required by the owner's C6
// layer-split decision
// (protected/us017-c6-layer-split-owner-decision-2026-08-28.json, sha256
// d41b5307de3a85f6e83d49767a366035139721eadb03be0efb4784af810bb8c6), which
// resolves C6 from protected/us017-post-failure-owner-decisions-2026-08-28.json
// (sha256 612546e8ee34cf6979d1258b0f2f020aeacfeedee3e22a291c4e4c9e6c474a33).
//
// Unlike the close-transition record, this divergence IS resolved in code —
// but only at one layer, and the point of the record is to say which layer and
// why the other two are correct as they stand.
//
// Appended AFTER the close-transition record so the committed hash chain's
// prefix is unchanged.
func layerSplitDefinitions() []Definition {
	return []Definition{
		{
			Subject: "org.java-websocket.websocketimpl.protocol-violation-close-reaction",
			RFCRefs: []string{"rfc6455#section-7.1.7", "rfc6455#section-5.2", "rfc6455#section-7.4.1"},
			RFCExpectation: "RFC 6455 section 7.1.7 says that when an endpoint fails the WebSocket connection it MUST " +
				"close the connection, and that where the failure is detected after the opening handshake completed the " +
				"endpoint SHOULD send a Close frame with an appropriate status code (1002 PROTOCOL_ERROR for the section 5.2 " +
				"violations: a reserved RSV bit set on a frame whose negotiated extensions define no meaning for it, or a " +
				"reserved opcode) before closing the connection. Dropping the TCP connection with no Close frame is the " +
				"behaviour reserved for cases where sending one is impossible or unsafe.",
			RFCValue: "send-1002-then-close: a protocol violation detected after the handshake is answered with a Close " +
				"frame carrying the appropriate status code, which is flushed before the connection goes away",
			JavaRef: "org.java_websocket.WebSocketImpl:decodeFrames",
			JavaObservation: "Shipped Java-WebSocket 1.6.0 reacts, and the reaction is unambiguous at the full-stack entry " +
				"point while being ABSENT at the Draft-level entry point the differential corpus measures — which is the " +
				"whole of this record. (A) FULL STACK: WebSocketImpl.decodeFrames (WebSocketImpl.java:391-419) wraps " +
				"draft.translateFrame and draft.processFrame in a try whose InvalidDataException arm " +
				"(WebSocketImpl.java:405-408) calls wsl.onWebsocketError(this, e) and then close(e). close(InvalidDataException) " +
				"(WebSocketImpl.java:631-633) delegates to close(e.getCloseCode(), e.getMessage(), false), and " +
				"close(int, String, boolean) (WebSocketImpl.java:463-507) — entered from OPEN because decode gates " +
				"decodeFrames on readyState == OPEN at WebSocketImpl.java:227-230 — fires onWebsocketCloseInitiated " +
				"(:474-480), builds a CloseFrame carrying the rejection's OWN close code and calls sendFrame (:481-487), " +
				"calls flushAndClose (:494) whose onWriteDemand comment states that it 'ensures that all outgoing frames are " +
				"flushed before closing the connection' (:594-595), and sets readyState = ReadyState.CLOSING (:503). CLOSED " +
				"arrives later through closeConnection (:530-567, readyState assignment at :566), reached from eot() " +
				"(:608-624) or, on the server, from SocketChannelIOHelper.batch once outQueue drains " +
				"(SocketChannelIOHelper.java:110-113). The single carve-out is CloseFrame.ABNORMAL_CLOSE (1006), which takes " +
				"WebSocketImpl.java:466-471 and reaches CLOSING with NO frame written. (B) DRAFT-LEVEL ADAPTER: the pinned " +
				"java-oracle drives the Draft directly — draft.translateFrame at OracleEngine.java:342-346 and " +
				"draft.processFrame at OracleEngine.java:387 — and never calls WebSocketImpl.decode/decodeFrames, so none of " +
				"the catch/close(e)/flushAndClose machinery above can run. Its step loop has no try/catch at all " +
				"(OracleEngine.java:311-322), so the first failure propagates out and aborts the scenario, and its failure " +
				"serializer (OracleEngine.java:591-606, against the success shape at :573-585) emits only outcome, error, " +
				"counts, final_state and runtime — it structurally cannot report a frame, a transition or a close. THE LIVE " +
				"RECORDING SHOWS WHICH ONE THE CORPUS PINS: the real pinned Java-WebSocket 1.6.0 runtime (jar sha256 " +
				"eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f) recorded all 18 public byte-path " +
				"JAVA_INVALID_DATA cases with final_state OPEN and no frame " +
				"(protected/us005-corpora/live/public/transcript.jsonl, 74/74 reconciled).",
			JavaValue: "entry-point-dependent: WebSocketImpl.decodeFrames answers a protocol violation with a close frame " +
				"carrying the rejection's own code and moves OPEN->CLOSING (WebSocketImpl.java:405-408, :481-487, :503), " +
				"while the Draft-level OracleEngine takes no action at all and the live recording keeps final_state open",
			AutobahnRefs: []string{"autobahn-v25.10.1:3.2", "autobahn-v25.10.1:4.1.1", "autobahn-v25.10.1:7.7.5"},
			AutobahnResult: "PROBATIVE AND MEASURED ON BOTH SIDES OF THE CHANGE, on the pinned image " +
				"crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074 " +
				"(pull=never), full case set 1.*/2.*/3.*/4.*/5.*/6.*/7.*/10.*, 247 cases both runs, wstest exit 0 both runs. " +
				"BEFORE the adapter reaction: all 17 section 3 (RSV violations) and section 4 (reserved opcodes) cases " +
				"recorded close_frames=0, remoteCloseCode null and wasNotCleanReason 'peer dropped the TCP connection " +
				"without previous WebSocket closing handshake'. AFTER: all 17 record close_frames=1, remoteCloseCode 1002 " +
				"and wasNotCleanReason null, with the behavior/behaviorClose grades unchanged (11 OK/OK, 6 NON-STRICT/OK). " +
				"Case 7.7.5 ('send close with valid close code 1007'), which our core rejects with JAVA_INVALID_DATA close " +
				"code 1007, improved from OK/UNCLEAN to OK/OK because the same reaction now answers it with a 1007 close " +
				"frame instead of a TCP drop. Whole-suite census moved from 106 to 107 OK/OK and 36 to 35 OK/UNCLEAN with " +
				"ZERO cases regressing and zero FAILED in either run.",
			AutobahnValue: "seam-divergence-closed: the 17 section-3/4 pure-violation cases go from close_frames=0 / " +
				"remoteCloseCode null / 'peer dropped the TCP connection' to close_frames=1 / remoteCloseCode 1002 / clean, " +
				"plus 7.7.5 UNCLEAN->OK, with 0 regressions across 247 cases",
			Rationale: "DIVERGENCE (protocol-violation reaction): the RFC and shipped WebSocketImpl answer a post-handshake " +
				"protocol violation with a Close frame; our stack answered with nothing and dropped TCP, because it is " +
				"Draft-level/oracle-faithful end to end. OWNER DECISIONS: " +
				"protected/us017-post-failure-owner-decisions-2026-08-28.json (sha256 " +
				"612546e8ee34cf6979d1258b0f2f020aeacfeedee3e22a291c4e4c9e6c474a33), decision id c6-match-java-fully, ruled " +
				"the stack must follow shipped WebSocketImpl, with a HARD STOP condition: surface rather than re-baseline if " +
				"the change shifts the live-oracle-confirmed 74-case transcript or moves scored-field disagreement with live " +
				"Java above zero. It did. Implemented first in rust/ws-core/src/connection.rs (react to a fatal " +
				"JAVA_INVALID_DATA raised on the byte path while Open: compose the close frame, transition Open->Closing), " +
				"the change moved EXACTLY 18 of the 74 public cases (us005.pub.0005, 0019, 0020, 0029, 0031, 0033, 0036, " +
				"0039, 0041, 0042, 0052, 0056-0059, 0065-0067) on final_state (open->closing) and counts.frames (+1), " +
				"taking scored-field disagreement with live Java from ZERO to 18 and corporactl evaluate from 74/74 exit 0 " +
				"to 74/56/18 exit 1. Every case and both fields were named in a prediction written BEFORE the first source " +
				"edit with an empty git status. The stop fired and was surfaced, not reconciled. RESOLUTION: " +
				"protected/us017-c6-layer-split-owner-decision-2026-08-28.json (sha256 " +
				"d41b5307de3a85f6e83d49767a366035139721eadb03be0efb4784af810bb8c6) ruled the LAYER SPLIT: PLACE THE REACTION " +
				"IN THE ADAPTER, NOT THE CORE. RESOLVED AT ONE LAYER, AND CORRECT AT EACH: (1) ws_core stays " +
				"oracle-faithful and is byte-identical to its pre-change state — it is the layer the live java-oracle " +
				"differential scores, and the corpus pins the Draft-level entry point (B above), so a reaction here would " +
				"make the port disagree with the very runtime it is verified against; (2) ws_driver likewise unchanged for " +
				"this record, being the single-owner seam the differential harness routes through; (3) ws_testee's io_loop " +
				"IS shipped-library-faithful at the wire, because Autobahn drives it in the full-stack peer role that " +
				"WebSocketImpl itself plays (A above), and that is the seam where the divergence was externally observable. " +
				"WHY THE SPLIT CANNOT LEAK: rust/ws-oracle-harness declares exactly two dependencies, ws-core and ws-driver, " +
				"and contains no reference to ws-testee, so an adapter-layer reaction is STRUCTURALLY unable to move a " +
				"corpus byte. MEASURED, not argued: after the placement the release harness binary rebuilt to the IDENTICAL " +
				"sha256 eef7d568…, the public transcript compared byte-identical (cmp exit 0, including the embedded " +
				"runtime object), corporactl evaluate read 74/74 exit 0, and scored-field disagreement with live Java " +
				"measured ZERO. WS_TESTEE SITE: " +
				"rust/ws-testee/src/io_loop.rs violation_close_frame / send_violation_close, pinned by the wire-level " +
				"regression rust/ws-testee/tests/loopback.rs::a_protocol_violation_gets_the_shipped_java_1002_close_on_the_wire " +
				"(paired negative control run: stubbing the reaction fails it at exit 101) and by six unit tests covering " +
				"the Java carve-outs — the OPEN guard (close's :464 guard), the no-close-code path (STATE_VIOLATION and the " +
				"limit codes, which never reach close(e)), the 1006 frameless path (:466-471), client-role masking, and the " +
				"rejection's own code reaching the wire for 1002/1007/1009. TWO DISCLOSED DEPARTURES FROM JAVA AT THIS SITE: " +
				"the close reason is EMPTY because TypedProtocolFailure carries no message and inventing one would put a " +
				"fabricated Java message on the wire; and the flush is bounded by the same US-018 write_stall_limit the " +
				"main write path carries, where Java's flushAndClose would block indefinitely — the adapter reports no " +
				"close frame when the peer stopped reading rather than claiming one that never left. DISPOSITION NOTE: " +
				"'unresolved' is the frozen 1.0.0 vocabulary's only retained-divergence term; ws_core's deliberate " +
				"Draft-level non-reaction is the retained half of this split, while the wire-observable half is resolved " +
				"in ws_testee.",
		},
	}
}
