package deltaledger

// autobahnCompositionDefinitions are the two divergences the merged E5
// Autobahn leg surfaced and left explicitly unledgered (protected
// e5-autobahn-receipt.json, java_comparison.divergences: 245/247 per-case
// behavior-class matches, 2 analyzed divergences).
//
// They are the FIRST ledger records whose autobahn_refs are executed
// observations rather than nominal anchors: the Rust side ran the pinned
// wstest image against ws-testee (247/247 executed, E5 commit 76158f35 and
// the E5b rerun) and the Java side has the recovered server-mode
// qualification receipt (13-qualification-pass.json, per-case behavior
// classes). Both records therefore carry their own
// autobahn_result/autobahn_value preimages instead of AutobahnResultMarker.
//
// Both are appended AFTER the 32 existing definitions so the committed
// hash chain's prefix is unchanged.
func autobahnCompositionDefinitions() []Definition {
	const e5Provenance = "AUTOBAHN (EXECUTED, not a nominal anchor): pinned image " +
		"crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074 " +
		"(suite 25.10.1), fuzzingclient mode against ws-testee, 247/247 cases executed in the merged E5 leg " +
		"(evidence/rust/autobahn-e5/) and re-executed 247/247 in the E5b leg (evidence/rust/autobahn-e5b/). The Java " +
		"side is the recovered server-mode qualification receipt 13-qualification-pass.json (247/247 executed, per-case " +
		"BEHAVIOR STATUS CLASS ONLY — it records no behaviorClose and no close codes, so no claim is made about WHICH " +
		"wstest-accepted observable live Java produced)."

	const disposition = " DISPOSITION NOTE: 'unresolved' is the frozen 1.0.0 vocabulary's only retained-divergence term; " +
		"under the recorded JAVA_FAITHFUL_PLUS_SAFE fidelity authority (owner decision " +
		"us010-016-ac-amendment-owner-decision-2026-08-27.json, sha256 " +
		"26849b5ea74006504d18507ac694c00e882e7fd37d4cd8c8502ea824e96ea974) the divergence is deliberately retained, not " +
		"resolved toward the RFC. Basis for this record: the merged E5 receipt's own finding that the site needed one."

	return []Definition{
		{
			Subject: "org.java-websocket.websocketimpl.close-echo-wire-composition",
			RFCRefs: []string{"rfc6455#section-5.5.1", "rfc6455#section-7.4.1"},
			RFCExpectation: "RFC 6455 section 5.5.1 says an endpoint answering a Close frame SHOULD echo the status " +
				"code it received, and section 7.4.1 makes 1002 the protocol-error code; a close frame whose payload is a " +
				"single byte is malformed, so the reply carries 1002 (Autobahn 7.3.2 accepts 1002 or a TCP drop).",
			RFCValue: "reply-1002: the wire close reply to a malformed 1-byte close frame carries code 1002",
			JavaRef:  "org.java_websocket.WebSocketImpl:close",
			JavaObservation: "The shipped full stack does NOT put the received close frame object back on the wire. " +
				"Draft_6455.processFrame routes CLOSING to processFrameClosing (drafts/Draft_6455.java:896-897), which " +
				"reads the DECODED cf.getCloseCode()/cf.getMessage() (drafts/Draft_6455.java:1055-1060) and, the draft's " +
				"handshake type being TWOWAY (drafts/Draft_6455.java:1111-1113), calls webSocketImpl.close(code, reason, " +
				"true) (drafts/Draft_6455.java:1067-1068). WebSocketImpl.close builds a BRAND NEW frame — new CloseFrame(); " +
				"setReason(message); setCode(code); isValid(); sendFrame(closeFrame) (WebSocketImpl.java:482-486) — whose " +
				"updatePayload writes the low two bytes of the code big-endian followed by the UTF-8 reason " +
				"(framing/CloseFrame.java:294-302). A 1-byte close payload decodes to PROTOCOL_ERROR 1002 " +
				"(framing/CloseFrame.java:252-253), so the wire reply is 1002. The core's Q19/Q10 echo instead carries the " +
				"CloseFrame CONSTRUCTOR payload [0x03,0xE8]: CloseFrame.setPayload overrides the base method and assigns " +
				"only the code/reason FIELDS, never super.setPayload (framing/CloseFrame.java:246-271), so the received " +
				"frame OBJECT keeps the constructor buffer (framing/CloseFrame.java:168-172 via " +
				"framing/FramedataImpl1.java:241-242) — and the java-oracle harness re-emits exactly that object " +
				"(java-oracle/src/main/java/OracleEngine.java:382). The core observable is therefore correct AT ITS LAYER " +
				"and live-oracle-confirmed; the composition one layer up is not the same bytes.",
			JavaValue: "compose-from-received: WebSocketImpl.close builds its own close frame carrying the received code " +
				"and reason (1002 for a 1-byte inbound close payload)",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.3.2"},
			AutobahnResult: "EXECUTED. Rust BEFORE the E5b adapter fix (evidence/rust/autobahn-e5/index-run1.json, agent " +
				"verified-rust-ws-testee-e5): 7.3.2 behavior FAILED, behaviorClose WRONG CODE, remoteCloseCode 1000 — the " +
				"Draft-level constructor-payload echo reached the wire. Rust AFTER the fix " +
				"(evidence/rust/autobahn-e5b/index-run1.json, agent verified-rust-ws-testee-e5b): 7.3.2 behavior OK, " +
				"remoteCloseCode 1002; 247/247 executed, 233 OK / 11 NON-STRICT / 3 INFORMATIONAL / 0 FAILED, and 7.3.2 is " +
				"the ONLY case whose behavior or behaviorClose class changed. Java server-mode qualification receipt: 7.3.2 " +
				"status OK. Per-case Java behavior-class agreement rose from 245/247 to 246/247.",
			AutobahnValue: "wire-close-code=1002 (post-fix, read from the Autobahn per-case report); pre-fix wire-close-code=1000",
			Rationale: "DIVERGENCE (close-echo wire composition, Autobahn 7.3.2): the ingredients were already ledgered at " +
				"the core-observable level — delta-d509ac380f51587105ed2fb3 (a 1-byte close payload is a VALID 1002 close) " +
				"and delta-954132f2fb781974 (the echo/record carries the constructor payload [0x03,0xE8]) — but their " +
				"WIRE-LEVEL COMPOSITION replied 1000 to a malformed close, which wstest scores WRONG CODE. FIDELITY " +
				"EVIDENCE: quarantined Java sites above, all read in the digest-pinned 1.6.0 tree. RESOLUTION (adapter " +
				"layer only): rust/ws-driver gained CloseEchoPolicy, defaulting to the shipped-Java " +
				"WebSocketImplComposition, which recomposes the core's Q19 echo write into the frame " +
				"WebSocketImpl.close would send (received code big-endian, then the reason), reusing the frame's own mask " +
				"key so the core's deterministic client-role mask sequence is undisturbed. ws_core is UNCHANGED: its " +
				"Q19/Q10 echo and " +
				"every semantic event, frame record and governing close detail are byte-identical, proven by a 74/74 " +
				"public-corpus run whose transcript is byte-identical (sha256 fd3f7a1c1eb0eeed0a7b214eac2dc517ab169511ce266" +
				"d98280f7eff571f2326) to the merged E5 baseline. WS_CORE SITE (unchanged, cited for the layer boundary): " +
				"rust/ws-core/src/connection.rs close echo arm; rust/ws-core/src/framing.rs constructor payload (Q10). " +
				"PORT SITE: rust/ws-driver/src/lib.rs (CloseEchoPolicy, compose_close_echo), pinned by " +
				"rust/ws-driver/tests/close_composition.rs and the end-to-end wire test " +
				"rust/ws-testee/tests/loopback.rs::autobahn_7_3_2_wire_reply_is_1002_end_to_end. SAFETY: the recomposition " +
				"is a bounded rewrite of one control frame (<=125 bytes) under forbid(unsafe_code) with zero new " +
				"dependencies; it emits no attacker-controlled bytes beyond the peer's own close reason, which shipped " +
				"Java also echoes, and it leaves the core's protocol state untouched." + disposition + " " + e5Provenance,
		},
		{
			Subject: "org.java-websocket.websocketimpl.batch-drain-echo-flush-ordering",
			RFCRefs: []string{"rfc6455#section-5.4", "rfc6455#section-7.1.7"},
			RFCExpectation: "RFC 6455 section 5.4 requires a completed fragmented message to be delivered, and section " +
				"7.1.7 permits an endpoint that detects a protocol violation to fail the connection immediately; the RFC " +
				"does not fix which of the two wins when one read carries a complete message AND a later poisoned frame.",
			RFCValue: "unordered: the RFC permits either the echo-then-fail or the fail-immediately observable",
			JavaRef:  "org.java_websocket.WebSocketImpl:decodeFrames",
			JavaObservation: "Shipped Java decodes the chop in TWO PHASES. Phase 1: WebSocketImpl.decodeFrames calls " +
				"draft.translateFrame ONCE (WebSocketImpl.java:394) and Draft_6455.translateFrame loops translateSingleFrame " +
				"over the whole buffer, returning a List of EVERY complete frame in the chop " +
				"(drafts/Draft_6455.java:724-773). Phase 2: decodeFrames then dispatches that list sequentially, " +
				"for (Framedata f : frames) draft.processFrame(this, f) (WebSocketImpl.java:395-398). So the poisoned frame " +
				"is DECODED before the echo exists; it is merely DISPATCHED later. The 5.15 poison survives phase 1 because " +
				"it is a SEQUENCE error, not a decode error: a lone CONTINUATION frame is structurally valid to " +
				"translateSingleFrame, and the violation is only raised in phase 2 at " +
				"Draft_6455.processFrameContinuousAndNonFin's currentContinuousFrame == null arm " +
				"(drafts/Draft_6455.java:934-937 — the FIN=false arm; Autobahn 5.15's own description says FIN = false, so " +
				"this is NOT the processFrameIsFin twin at :1001-1004). Dispatching the SECOND fragment completes the " +
				"message and reaches the echo listener, whose send enqueues the echo into outQueue and raises a write " +
				"demand (WebSocketImpl.send(Collection):667-681 -> write(List):749-755 -> write(ByteBuffer):736-742, " +
				"outQueue.add at :740 and wsl.onWriteDemand at :741) — all BEFORE the third frame is dispatched. Dispatching " +
				"the third frame throws; decodeFrames catches it at WebSocketImpl.java:405-408 and calls close(e) -> " +
				"close(1002, ...) (:631-633 -> :463), which enqueues Java's own close frame (:482-486) and then calls " +
				"flushAndClose (:494). flushAndClose raises the FINAL write demand (WebSocketImpl.java:594-595) whose own " +
				"in-source comment is 'ensures that all outgoing frames are flushed before closing the connection'. Java " +
				"therefore never discards already-queued output on a protocol failure. The Rust adapter differs earlier and " +
				"more sharply: the echo is never even ENQUEUED, because ws_core's typed failure short-circuits the poll " +
				"before the completed message's Text event is DELIVERED (ws_driver finish_poll returns DriverOutput::Failure " +
				"without draining queued events, rust/ws-driver/src/lib.rs:599-611; rust/ws-testee/src/io_loop.rs:221-225 " +
				"then shuts the socket and breaks), so the adapter's event-driven echo policy never runs — confirmed by the " +
				"adapter session line for 5.15 reading texts=0 (evidence/rust/autobahn-e5b/serve-run2.log session=7).",
			JavaValue: "enqueue-then-flush: the completed message's echo is enqueued during the earlier dispatch and the " +
				"queued output is flushed on the failure path, so the echo reaches the wire before the connection closes",
			AutobahnRefs: []string{"autobahn-v25.10.1:5.15"},
			AutobahnResult: "EXECUTED. Rust (evidence/rust/autobahn-e5/index-run1.json and " +
				"evidence/rust/autobahn-e5b/index-run1.json, both runs): 5.15 behavior NON-STRICT, behaviorClose OK — " +
				"stable across four executions (E5 run1/run2, E5b run1/run2). Java server-mode qualification receipt: 5.15 " +
				"status OK. Both classes are wstest-passing; this is the ONLY remaining per-case class difference " +
				"(246/247 agreement after the 7.3.2 fix).",
			AutobahnValue: "rust=NON-STRICT (received=[]), java=OK; the 5.15 per-case report's own expectation map is " +
				"{NON-STRICT: [], OK: [['message','fragment1fragment2',false]]}, so the Java receipt's OK class entails " +
				"that live Java echoed the completed message — unlike 7.3.2, the OK class here admits exactly one observable",
			Rationale: "DIVERGENCE (dispatch-phase echo enqueue vs fail-before-delivery, Autobahn 5.15): the fuzzer sends a " +
				"complete 2-fragment text message, a CONTINUATION frame with FIN=false where there is nothing to continue, " +
				"and an unfragmented text, all in ONE chop. Java translates the whole chop first, then dispatches frame by " +
				"frame, so the echo is ENQUEUED during the second fragment's dispatch and the failure path's flushAndClose " +
				"write demand flushes it; the Rust adapter's typed failure lands before the completed message's Text event " +
				"is delivered, so the echo is never enqueued at all. RFC 6455 7.1.7 permits immediate fail-on-violation, so " +
				"the Rust side is the RFC-STRICTER behavior and Autobahn classes both as passing (OK vs NON-STRICT). " +
				"MECHANISM CORRECTION (review round 2, session 01a045b9-7292-7961-9483-211103fdf53d): this record's first " +
				"preimage said Java 'decodes and dispatches ONE frame at a time' and that the echo flushed BEFORE the " +
				"poisoned frame was decoded. That was wrong and was corrected against the pinned source: translateFrame " +
				"decodes ALL complete frames up front, so the poisoned frame is decoded first and only DISPATCHED later. " +
				"FIDELITY EVIDENCE: protected e5-autobahn-receipt.json java_comparison.divergences[5.15]; per-case reports " +
				"evidence/rust/autobahn-e5/cases-run1/ and evidence/rust/autobahn-e5b/cases-run1/. RELATED LEDGER RECORDS " +
				"(same family, different sites): delta-b375f7126b944afad6a75453a1871d (post-payload rejection site) and " +
				"delta-4e6bffb12b05856babb99a3df92f45 (consumed-bytes error sites). NOT RESOLVED IN CODE: unlike the 7.3.2 " +
				"composition, this ordering lives in the adapter's drain strategy over a bounded batch, and changing it " +
				"would trade an RFC-stricter observable for a Java-faithful one with no Autobahn class gain; it is recorded " +
				"as a retained divergence pending an owner fidelity decision. WS_CORE SITE: rust/ws-core/src/connection.rs " +
				"process_inbound (the typed failure ends the input); PORT SITES: rust/ws-driver/src/lib.rs finish_poll " +
				"(a failure is surfaced without draining queued events) and rust/ws-testee/src/io_loop.rs drain loop " +
				"(ProtocolFailure shuts the socket and breaks). SAFETY: failing earlier is strictly the " +
				"safer of the two observables — no bytes are emitted after a detected protocol violation." +
				disposition + " " + e5Provenance,
		},
	}
}
