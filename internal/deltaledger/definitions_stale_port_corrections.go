package deltaledger

// TWO SUPERSEDING RECORDS FOR TWO PORTS THAT NO LONGER EXIST.
//
// Sequences 34 and 55 each describe the port's behaviour in the present tense,
// and each description became false when a LATER branch landed a fix. Neither
// record was touched, so the chain carries an open question about a program
// that is not the program on disk. F010 named it for sequence 55 and the DIV-05
// continuation named it for sequence 34, both on 2026-09-03; this file is the
// correction, under the same SUPERSEDE-DO-NOT-REWRITE ruling that sequences
// 45-47 were appended under, and appended LAST so every existing record keeps
// its sequence, previous_digest and record_digest.
//
// WHAT EACH SUPERSESSION CLAIMS, AND WHAT IT DELIBERATELY DOES NOT.
//
// Sequence 34 (Autobahn 5.15 dispatch-phase echo): the superseded record says
// the port's typed failure lands before the completed message is delivered, so
// "the echo is never enqueued at all". Measured on the full-stack path today,
// the port writes the echo and THEN the 1002 close — shipped Java's order. The
// superseding record states that, states the layer split that keeps the OLD
// ordering on the oracle path, and states the one thing it does not settle:
// sequence 54 wrote a precondition ("if the reproduction shows the port cannot
// enqueue the echo without breaking the ordering ledgered at sequence 34") that
// the DIV-05 landing never tested, because it took the general mechanism rather
// than showing a narrower one impossible.
//
// Sequence 55 (server 101 response fields): the superseded record says the port
// omits Server and Date and does not sort its field names. The port now emits
// all five fields in Java's case-insensitive order, byte-exact against the
// pinned JAR's own output. The Java-versus-port divergence that record binds is
// CLOSED. The disposition stays `unresolved` for a DIFFERENT reason than the
// one that record gave, and the new reason is the whole point of the
// supersession: US-011 AC2 forbids in as many words the two fields the port now
// emits, so the port is now on the wrong side of a PROJECT criterion instead of
// silent on an RFC-open one.
//
// THE CLASS ON BOTH RECORDS IS `underspecified-behavior`, AND F013 IS WHY IT IS
// WRITTEN OUT RATHER THAN LEFT TO READ ITSELF. That finding shows the class was
// being used to mean "nothing determines this" when it means "RFC 6455 does not
// determine this", and that the difference is exactly what let sequence 55
// conclude its question was open while US-011 AC2 had answered it. So each
// rationale below says which authority is silent and which is not, in its own
// hashed bytes.

func staleOrderingCorrectionDefinitions() []Definition {
	return []Definition{
		batchDrainOrderingCorrection(),
		serverResponseFieldsCorrection(),
	}
}

// batchDrainOrderingCorrection supersedes sequence 34.
func batchDrainOrderingCorrection() Definition {
	return Definition{
		Subject: "org.java-websocket.websocketimpl.batch-drain-echo-flush-ordering.corrected",
		Supersedes: []Supersession{{
			Sequence: 34,
			DeltaID:  "delta-71c02bf6294792a4689c89bbd4c9b859c5667215e311dd6059013e14b7809ee8",
			Subject:  "org.java-websocket.websocketimpl.batch-drain-echo-flush-ordering",
			Reason:   "the-port-behaviour-it-describes-is-pre-div05-the-full-stack-now-dispatches-one-frame-per-turn",
			Authority: "protected/ledger-frozen-prefix-owner-decision-2026-08-28.json" +
				"@sha256:bb3cd0da7f4aed014290dab3dc35b2ec87f41d3d7e7a8c7449816159e9d837c7",
		}},
		RFCRefs: []string{"rfc6455#section-5.4", "rfc6455#section-7.1.7"},
		RFCExpectation: "RFC 6455 section 5.4 requires a completed fragmented message to be delivered and section " +
			"7.1.7 permits an endpoint to fail the connection immediately upon detecting a protocol violation. " +
			"Neither clause fixes which of the two wins when ONE read carries both a completed message and a later " +
			"violating frame, so the RFC does not determine the ordering of the completed message's application echo " +
			"against the failure reaction.",
		RFCValue: "unordered: the RFC permits either the echo-then-fail or the fail-immediately observable, and " +
			"conformance does not distinguish them",
		JavaRef: "org.java_websocket.WebSocketImpl:decodeFrames",
		JavaObservation: "PINNED SOURCE, NO JAVA PROCESS RAN FOR THIS RECORD (Java-WebSocket 1.6.0, commit " +
			"da3cf2a777aed862f2f5b5cf060cae7969958667): decodeFrames translates the WHOLE socket buffer in one call " +
			"(WebSocketImpl.java:394) and then walks the resulting list ONE FRAME AT A TIME (:395-398); " +
			"Draft_6455.processFrame dispatches TEXT to processFrameText (Draft_6455.java:982-990), which calls " +
			"onWebsocketMessage SYNCHRONOUSLY inside that iteration, so an echoing listener's frame is already in " +
			"outQueue (WebSocketImpl.java:640-646, :667-680) before the NEXT iteration reaches the violating frame; " +
			"the failure path's flushAndClose write demand (:592-595) then flushes it and " +
			"SocketChannelIOHelper.batch hangs up only once outQueue is empty (SocketChannelIOHelper.java:110-113). " +
			"These citations are transcribed in rust/ws-driver/src/lib.rs on InboundFeedPolicy and were re-read at " +
			"that site for this record.",
		JavaValue: "echo-then-close: the completed message's echo is enqueued during its own dispatch and reaches " +
			"the wire before the violation close",
		AutobahnRefs: []string{"autobahn-v25.10.1:5.15"},
		// AutobahnResult and AutobahnValue stay EMPTY on purpose. Sequence 34
		// carries executed E5/E5b preimages; those runs measured the PRE-fix
		// subject, this record is about the post-fix one, and re-running the
		// suite is an owner gate. Inheriting an executed marker for a subject
		// the run never saw would be the overclaim this whole file is about.
		Disposition:   "adopt-java",
		MismatchClass: "underspecified-behavior",
		Rationale: "SUPERSEDING CORRECTION for ledger sequence 34 (Autobahn 5.15 dispatch-phase echo). WHAT THE " +
			"SUPERSEDED RECORD SAYS ABOUT THE PORT IS NOW FALSE: it states that the port's typed failure lands " +
			"before the completed message's Text event is delivered, so the echo is never enqueued at all. MEASURED " +
			"TODAY, same wire in one chop: `cargo test -p ws-testee --test close_overtakes_echo " +
			"the_autobahn_5_15_chop` EXIT 0, and the pinned assertion is the frame shape [(0x1,18),(0x8,2)] — the " +
			"reassembled echo `fragment1fragment2` FIRST and the 1002 close AFTER. The port writes shipped Java's " +
			"order. WHAT MOVED IT: the DIV-05 fix ledgered at sequence 54 added " +
			"ws_driver::InboundFeedPolicy::OneFramePerTurn, which is the full-stack constructor's setting " +
			"(rust/ws-driver/src/lib.rs connection_driver) and is Java's decodeFrames per-frame dispatch loop; the " +
			"side effect on this subject was pinned at " +
			"rust/ws-testee/tests/close_overtakes_echo.rs::the_autobahn_5_15_chop_now_returns_the_completed_echo_" +
			"before_the_violation_close rather than left silent. TWO OBSERVABLES, NOT ONE: the ORACLE path keeps " +
			"InboundFeedPolicy::WholeChunk, the default, because the public corpus scores its input_chunk records, " +
			"so the pre-fix ordering is still the oracle observable and that layer split is the subject of the " +
			"record at sequence 49. This record's claim is scoped to the FULL-STACK path, which is the path " +
			"Autobahn 5.15 exercises. MISMATCH CLASS underspecified-behavior, WITH ITS SCOPE STATED: it means RFC " +
			"6455 does not determine this observable — 5.4 and 7.1.7 admit both orderings and the suite classes " +
			"both as passing. It does NOT mean nothing determines it: the recorded JAVA_FAITHFUL_PLUS_SAFE fidelity " +
			"authority makes shipped Java the equivalence target wherever the RFC is silent and no named safety " +
			"bound is at stake, and a dispatch ordering is none of unsafe code, bounded allocation, backpressure, a " +
			"checked config limit or a hard safety ceiling. DISPOSITION adopt-java: the port reproduces shipped " +
			"Java, measured above, and that authority is what licenses it. WHAT THIS RECORD DOES NOT SETTLE, named " +
			"because it is the reason a reader might expect `unresolved`: sequence 54 wrote a precondition — if the " +
			"port CANNOT enqueue the echo without breaking the ordering ledgered at sequence 34, that finding " +
			"supersedes its disposition and the record becomes one for a preserved ordering. The DIV-05 landing " +
			"never tested that antecedent; it took the general mechanism and did not show a narrower fix " +
			"impossible. If the owner rules the side effect should be reverted, THIS disposition is the thing that " +
			"changes, and it is recorded here so that ruling has something to overturn. NO AUTOBAHN CLAIM IS MADE: " +
			"the executed E5/E5b legs carried by sequence 34 measured the pre-fix subject, re-running the suite is " +
			"an owner gate, and this record's Autobahn preimages are therefore the honest non-execution markers." +
			frozenPrefixOwnerDecision,
	}
}

// serverResponseFieldsCorrection supersedes sequence 55.
func serverResponseFieldsCorrection() Definition {
	return Definition{
		Subject: "org.java-websocket.draft6455.server-handshake.response-server-and-date-fields.corrected",
		Supersedes: []Supersession{{
			Sequence: 55,
			DeltaID:  "delta-34db0ad7c9378f88a8b9ddd66d76f9d7323c46a13e89ca04bfac51ea6f273830",
			Subject:  "org.java-websocket.draft6455.server-handshake.response-server-and-date-fields",
			Reason:   "the-port-behaviour-it-describes-is-pre-div06-the-response-now-carries-all-five-fields-in-javas-order",
			Authority: "protected/ledger-frozen-prefix-owner-decision-2026-08-28.json" +
				"@sha256:bb3cd0da7f4aed014290dab3dc35b2ec87f41d3d7e7a8c7449816159e9d837c7",
		}},
		RFCRefs: []string{"rfc6455#section-4.2.2"},
		RFCExpectation: "RFC 6455 section 4.2.2 fixes the fields the server's 101 response is REQUIRED to carry — " +
			"Upgrade, Connection and Sec-WebSocket-Accept — and neither requires nor forbids a Server or a Date " +
			"field. Under RFC 7230 the order of differently named header fields is not significant.",
		RFCValue: "no-requirement: the RFC neither mandates nor prohibits Server or Date on the 101 response and " +
			"fixes no field order, so a three-field response and a five-field response both conform",
		JavaRef: "org.java_websocket.drafts.Draft_6455:postProcessHandshakeResponseAsServer",
		JavaObservation: "PINNED SOURCE plus a byte-exact port test against the pinned JAR's own recorded output: " +
			"postProcessHandshakeResponseAsServer writes FIVE fields (Draft_6455.java:434, :435-436, :441, :449, " +
			":450), HandshakedataImpl1's TreeMap under String.CASE_INSENSITIVE_ORDER sorts them " +
			"(HandshakedataImpl1.java:50) and Draft.createHandshake writes them in that order (Draft.java:275-283), " +
			"giving Connection, Date, Sec-WebSocket-Accept, Server, Upgrade with the literal banner value " +
			"TooTallNate Java-WebSocket.",
		JavaValue: "five fields in String.CASE_INSENSITIVE_ORDER, including a Server banner naming the Java " +
			"library and a wall-clock Date",
		AutobahnRefs:  []string{"autobahn-v25.10.1:1.1.1"},
		Disposition:   "unresolved",
		MismatchClass: "underspecified-behavior",
		Rationale: "SUPERSEDING CORRECTION for ledger sequence 55 (server 101 response fields). WHAT THE " +
			"SUPERSEDED RECORD SAYS ABOUT THE PORT IS NOW FALSE: it opens by stating that the port's response omits " +
			"the Server and Date fields shipped Java adds and does not sort its field names. MEASURED TODAY: " +
			"`cargo test -p ws-core --test handshake_server_response` EXIT 0, 8 of 8 tests, pinning that the 101 " +
			"response carries Connection, Date, Sec-WebSocket-Accept, Server, Upgrade in " +
			"String.CASE_INSENSITIVE_ORDER and that it is byte-exact against the pinned JAR's own output. The " +
			"emission sites are rust/ws-core/src/handshake/server.rs accept_response, which writes the Date field " +
			"and the literal Server banner unconditionally. SO THE JAVA-VERSUS-PORT DIVERGENCE THIS RECORD BINDS IS " +
			"CLOSED, and the superseded record's reason for standing open is gone. WHY THE DISPOSITION IS STILL " +
			"unresolved, FOR A DIFFERENT REASON: US-011 AC2 requires the 101 response to carry the required headers " +
			"and NO Java-specific Date or Server banner, so the port now emits precisely what a criterion of its " +
			"own story forbids, and a test pins that it does. That conflict is between the PORT and a PROJECT " +
			"SPECIFICATION, and this ledger's authority model has one normative pole (RFC 6455) plus three " +
			"observation sources with no field for a project criterion, so the conflict can only be stated here. " +
			"THE RULING OWED, IN ONE LINE: either US-011 AC2 stands and the Server banner and Date are removed " +
			"while the Connection-echo half of the same landing is kept, or AC2 is AMENDED to permit a vendor " +
			"banner — an amendment, not a reading, because no parse of the clause permits a field whose value names " +
			"the Java library. MISMATCH CLASS underspecified-behavior, WITH ITS SCOPE STATED SO IT IS NOT READ AS " +
			"THE SUPERSEDED RECORD'S WAS: it means RFC 6455 4.2.2 does not determine this observable. It does NOT " +
			"mean nothing determines it — US-011 AC2 does, and recording the RFC's silence as silence full stop is " +
			"what let the superseded record conclude the question was open. NOT AN INDEPENDENT COUNT AGAINST THE " +
			"DATE FIELD: accept_response takes the instant as a PARAMETER and reads no clock, so the response is a " +
			"deterministic function of its inputs and AC2's determinism clause is satisfied; the clock lives in the " +
			"caller. NO AUTOBAHN CLAIM IS MADE: re-running the suite is an owner gate and this record's Autobahn " +
			"preimages are the honest non-execution markers." + frozenPrefixOwnerDecision,
	}
}
