package deltaledger

// THE SEVEN RECORDS THAT WERE WAITING FOR A VOCABULARY.
//
// Each of these was drafted, complete, under drafts/ledger-proposals/ and left
// unappended. The drafts say why in their own words: the ledger's disposition
// enum admitted only "unresolved" and "rfc-governs", and not one of the seven
// is either of those. One is a divergence the port ADOPTS in order to match
// shipped Java (the role-gated transport close). Five are places the port is
// short of its equivalence target and the remedy is a change in the PORT. One
// is a difference the port keeps DELIBERATELY and discloses. The 1.2.0
// vocabulary can say all three, so they land here.
//
// EVERY DIGEST PREIMAGE BELOW IS THE DRAFT'S, BYTE FOR BYTE. The six preimages
// of a record — RFC expectation and value, Java observation and value, Autobahn
// result and value — plus its subject, Java reference and reference sets are
// what the disagreement digest and therefore the delta identity are computed
// from. Each definition here reproduces the drafted delta_id exactly, and
// VerifyProposalDraftsAreLedgered recomputes that from the committed draft
// files rather than taking it on trust, so a reworded preimage fails the gate
// instead of quietly minting a different record.
//
// THE RATIONALE IS NOT THE DRAFT'S, AND THAT IS DELIBERATE. The rationale is
// the one field outside the disagreement-digest preimage (the drafts say so
// themselves), and each draft's rationale ends in a RECOMMENDATION written for
// a reader who could not record it — DIV-01's says in as many words that "until
// such a re-run exists the record stays unresolved", which would contradict the
// disposition this record now carries. Each rationale below keeps the draft's
// measured extent and evidence verbatim and replaces the recommendation with
// the ADJUDICATION actually made, argued from that evidence.
//
// HOW THE ADJUDICATIONS WERE MADE, stated once here rather than seven times:
//
//   - The MISMATCH CLASS follows where the mismatch originates. RFC determinate
//     and Java on the other side of it: java-quirk. Java and the RFC agreeing
//     and the port short of both, or Java the equivalence target on a point the
//     RFC leaves open and the port not reproducing it: rust-defect. The RFC not
//     determining the observable at all and Java and the port each choosing
//     differently: underspecified-behavior.
//   - The DISPOSITION is the draft's own recommendation WHERE THE EVIDENCE
//     SETTLES IT, and "unresolved" where it does not. It does not settle it
//     when the two candidate answers trade off something only the owner can
//     weigh — holding a socket a peer has already misused (DIV-03), putting a
//     clock into a deterministic core (DIV-06). A condition that is merely WORK
//     the port can do, such as DIV-05's reproduction, does not make the
//     disposition unresolved; it makes it a fix with a stated precondition.

func adjudicatedDefinitions() []Definition {
	return []Definition{
		// ------------------------------------------------------------------
		// drafts/ledger-proposals/server-close-parity.json
		// delta-516914f1e75aaf2c86bd082772a98b204ee217f86b54cecca648826688e40b82
		{
			Subject: "org.java-websocket.adapter.role-gated-transport-close",
			RFCRefs: []string{"rfc6455#section-5.5.1", "rfc6455#section-7.1.1", "rfc6455#section-7.1.2"},
			RFCExpectation: "RFC 6455 section 5.5.1: an endpoint closes the underlying TCP connection after BOTH sending and " +
				"receiving a Close message; the server closes first and the client waits for it (section 7.1.1).",
			RFCValue: "close the TCP connection only after a Close has both been sent and been received; server closes " +
				"first, client waits",
			JavaRef: "org.java_websocket.SocketChannelIOHelper:batch",
			JavaObservation: "PINNED SOURCE (Java-WebSocket 1.6.0, commit da3cf2a777aed862f2f5b5cf060cae7969958667): " +
				"SocketChannelIOHelper.java:110-113 closes the TCP connection when the out queue is empty, the " +
				"connection is flush-and-close, and the draft's role is SERVER; its only caller is the server " +
				"write path WebSocketServer.java:586. closeConnection() (WebSocketImpl.java:573-578) closes the " +
				"channel at WebSocketImpl.java:546. flushandclosestate is set by flushAndClose " +
				"(WebSocketImpl.java:592), reached from close(int,String,boolean) at WebSocketImpl.java:494 on " +
				"the same path that moves readyState to CLOSING at :503, for a peer close echoed via " +
				"Draft_6455.java:1068 and for a locally initiated close alike. " +
				"WebSocketClient.WebsocketWriteThread.runWriteData (WebSocketClient.java:837-851) has no " +
				"counterpart: the client closes its socket only when the write thread ends.",
			JavaValue: "server closes the TCP connection as soon as its own close frame has flushed, whether or not a " +
				"Close has been received; client never closes on this path",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.1.1"},
			// AutobahnResult and AutobahnValue stay empty: the honest
			// non-execution markers. No Autobahn run was executed for this
			// record and its refs are nominal anchors.
			Disposition:   "adopt-java",
			MismatchClass: "java-quirk",
			Rationale: "DIVERGENCE (adapter transport policy, role-gated TCP close at the end of the close handshake). " +
				"WHAT JAVA DOES: shipped Java closes the TCP connection from the SERVER side and never from the client " +
				"side. SocketChannelIOHelper.batch (pinned commit da3cf2a777aed862f2f5b5cf060cae7969958667, " +
				"SocketChannelIOHelper.java:110-113) closes the connection when the out queue is empty, the connection is " +
				"flush-and-close and the draft's role is SERVER; its only caller is the server write path " +
				"WebSocketServer.java:586, and closeConnection() (WebSocketImpl.java:573-578) closes the channel at :546 " +
				"and reports the governing close at :557. The client has no counterpart: " +
				"WebSocketClient.WebsocketWriteThread.runWriteData (WebSocketClient.java:837-851) closes its socket only " +
				"when the write thread itself ends, so a client that has echoed a close waits for the server to hang up. " +
				"WHAT THE PORT DID: neither role closed — the Sans-I/O core owns no socket and the adapter loop waited " +
				"for the peer's EOF, so a peer of the Rust server received the close echo and then nothing. WHAT THE PORT " +
				"DOES NOW: rust/ws-testee/src/io_loop.rs carries Java's gate verbatim as server_closes_transport(role, " +
				"state) — role == Role::Server && state == ReadyState::Closing — consulted only on the drained (Idle) " +
				"path, which is this side's image of outQueue.isEmpty(); ReadyState::Closing is this side's image of " +
				"isFlushAndClose(), since Java sets flushandclosestate in flushAndClose (WebSocketImpl.java:592) on the " +
				"same path that moves readyState to CLOSING (:494 and :503), for an echoed close (Draft_6455.java:1068) " +
				"and a locally initiated one alike. On the gate the adapter shuts the socket down and then hands the core " +
				"TransportEof, mirroring Java closing the channel (:546) before reporting the close (:557). " +
				"MISMATCH CLASS java-quirk: RFC 6455 section 5.5.1 is DETERMINATE here — the TCP connection is closed " +
				"after a Close has both been sent and been received, server first (7.1.1) — and shipped Java is on the " +
				"other side of it, because its gate is isFlushAndClose(), not 'a Close has been received'. A Java SERVER " +
				"that INITIATES a close therefore hangs up as soon as its own close frame has flushed, which 5.5.1 does " +
				"not permit. The mismatch originates in Java: not in the port, and not in any silence of the RFC. " +
				"DISPOSITION adopt-java: the port now reproduces that gate, the RFC-divergent initiated-close half " +
				"included, because the equivalence target is shipped Java 1.6.0 with its quirks. For the ECHOED close " +
				"Java and the RFC agree and the same change is a fidelity FIX; only the initiated-close half is the " +
				"divergence this record binds. EVIDENCE: rust/ws-testee/tests/loopback.rs — " +
				"a_server_closes_the_tcp_connection_once_its_close_echo_has_drained and " +
				"the_server_fixture_reaches_its_terminal_without_the_peer_ever_closing pin the echo case against a raw " +
				"TCP peer that never closes its own side; a_server_that_initiates_a_close_hangs_up_without_waiting_for_" +
				"the_echo pins the RFC-divergent sub-case against a peer that sends nothing at all; " +
				"a_client_does_not_close_the_tcp_connection_after_its_close_echo pins the client half of the role gate. " +
				"SCOPE: adapter transport policy only — ws-core and ws-driver are unchanged by it. JAVA EVIDENCE CLASS: " +
				"the Java observation is the PINNED SOURCE read directly, not an executed observation, because the " +
				"java-oracle adapter is a JSONL request/response oracle that never runs a real server socket, so no live " +
				"Java run on this plane observes which endpoint closes TCP. AUTOBAHN: leg not executed; the refs are " +
				"nominal anchors carrying the honest non-execution markers.",
		},

		// ------------------------------------------------------------------
		// drafts/ledger-proposals/divergence-sweep-1.json (DIV-01)
		// delta-6505983eb4eea7cd99d6d9ff497da1c95e8a5e2c490824504216625cf510d163
		{
			Subject: "org.java-websocket.websocketimpl.failure-close-frame-emission",
			RFCRefs: []string{"rfc6455#section-7.1.7", "rfc6455#section-7.4.1"},
			RFCExpectation: "RFC 6455 7.1.7 requires an endpoint that fails the WebSocket connection to send a Close frame " +
				"with an appropriate status code before closing the TCP connection, unless it has already " +
				"received one or cannot determine the status.",
			RFCValue: "close_frame_sent_on_failure=true; close_code=an appropriate 7.4.1 code; " +
				"close_reason=implementation-defined",
			JavaRef: "org.java_websocket.WebSocketImpl:close",
			JavaObservation: "Shipped Java 1.6.0 answers an InvalidDataException raised by Draft_6455.translateFrame or " +
				"processFrame by calling WebSocketImpl.close(code, message, false), which composes a CloseFrame " +
				"carrying the exception's close code and its message text, sends it, and only then calls " +
				"flushAndClose. Observed on the native x86_64 run in 3 distinct close codes and 32 distinct " +
				"reason strings, including 'bad rsv RSV1: false RSV2: false RSV3: true', 'more than 125 octets', " +
				"'Unknown opcode 3', 'closecode must not be sent over the wire: 1004' and 'Received text is no " +
				"valid utf8 string!'.",
			JavaValue: "subject_close_code in {1000,1002,1007}; subject_close_reason=the InvalidDataException message; " +
				"tcp_end=after the closing handshake",
			AutobahnRefs: []string{"autobahn-v25.10.1:2.5", "autobahn-v25.10.1:3.1", "autobahn-v25.10.1:6.3.1",
				"autobahn-v25.10.1:7.1.3"},
			AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa " +
				"(ws-testee), same host and same 247-case manifest as the Java baseline. MEASURED EXTENT (native " +
				"x86_64 run, 247-case pinned manifest, both roles): server role 122/247 cases, client role " +
				"119/247 cases. On every case in that set the port's subject_close_code is null (no close frame " +
				"reached the suite) where Java's is 1007 (76 server / 76 client), 1002 (42 server / 40 client) or " +
				"1000 (4 server / 3 client). On every case where the port DID send a close frame the code and the " +
				"reason equal Java's: 0 code disagreements and 0 reason disagreements among the cases where both " +
				"spoke. The Autobahn behaviour class hides this: both subjects score OK on most of the set. The " +
				"extent above is recomputed from the committed per-case report bytes by internal/divergencesweep " +
				"and recorded per case in evidence/java/observed-close-divergences.json; the digest manifest over " +
				"the 1048 pinned files is verified before any report is read, and internal/divergencesweep's " +
				"tests refuse a document that disagrees with the reports.",
			AutobahnValue: "port subject_close_code=null, subject_close_reason=null; java subject_close_code in " +
				"{1000,1002,1007} with 32 distinct reason strings",
			Disposition:   "fix-in-port",
			MismatchClass: "rust-defect",
			Rationale: "DIVERGENCE (failure without a Close frame): shipped Java answers a protocol failure with a Close " +
				"frame carrying the failing exception's code and message and then closes; the port's Autobahn adapter " +
				"dropped the TCP connection with nothing on the wire. MEASURED EXTENT (native x86_64 run, 247-case " +
				"pinned manifest, both roles): server role 122/247 cases, client role 119/247 cases; on every case in " +
				"that set the port's subject_close_code is null where Java's is 1007, 1002 or 1000, and on every case " +
				"where the port DID speak its code and reason equal Java's. MISMATCH CLASS rust-defect: RFC 6455 7.1.7 " +
				"and shipped Java AGREE here — both say a failed connection is answered with a Close frame carrying an " +
				"appropriate 7.4.1 code — so this is not an RFC-versus-Java question at all. The port was short of both, " +
				"and the mismatch originates in the port. DISPOSITION fix-in-port: the remedy is a change in the Rust " +
				"port, unconditionally; there is no owner tradeoff to weigh, because emitting the close frame adds one " +
				"bounded write on a path that already terminates the connection, with no unbounded buffering and no new " +
				"panic path, and a peer that logs or branches on the close code and reason sees a different program " +
				"without it. STATUS OF THAT FIX AT THIS APPEND: the change the sweep names — 'ws-testee: answer a " +
				"protocol violation the way shipped Java does', commit 77d8c23 — IS in mainline; " +
				"rust/ws-testee/src/io_loop.rs::send_violation_close is present and " +
				"rust/ws-testee/tests/loopback.rs::a_protocol_violation_gets_the_shipped_java_1002_close_on_the_wire " +
				"pins it at the wire. What is NOT done is the RE-MEASUREMENT: the extent above is the 518b77aa build, " +
				"and re-running the Autobahn suite is an owner gate that has not been exercised, so this record's " +
				"per-case set stands as the acceptance criterion the fix must be measured against and no claim is made " +
				"here that the count is now zero. TWO DISCLOSED RESIDUALS in the landed fix: the close reason is EMPTY " +
				"because the typed failure carries no message and inventing one would put a fabricated Java string on " +
				"the wire, and the flush is bounded by the write-stall limit where Java's flushAndClose would block " +
				"indefinitely. The extent above is recomputed from the committed per-case report bytes by " +
				"internal/divergencesweep and recorded per case in evidence/java/observed-close-divergences.json.",
		},

		// ------------------------------------------------------------------
		// drafts/ledger-proposals/divergence-sweep-2.json (DIV-02)
		// delta-fd4695dfb08c42f2fd9797a1bee4232305059db86f5c4e93ffc0414601916567
		{
			Subject: "org.java-websocket.websocketimpl.server-tcp-close-after-close-handshake",
			RFCRefs: []string{"rfc6455#section-7.1.1"},
			RFCExpectation: "RFC 6455 7.1.1 says the server closes the underlying TCP connection first, and the client should " +
				"wait for the server to do so; an endpoint may close it if it has not been closed after a reasonable delay.",
			RFCValue: "tcp_closed_by=server, once the closing handshake is complete",
			JavaRef:  "org.java_websocket.WebSocketImpl:closeConnection",
			JavaObservation: "Shipped Java 1.6.0 finishes the closing handshake through flushAndClose, whose write demand flushes " +
				"the pending close frame, after which closeConnection cancels the selection key and calls channel.close(). " +
				"The server end of the socket therefore goes away without the client acting. Observed on the native x86_64 " +
				"run as the suite recording droppedByMe=false on the Java server leg.",
			JavaValue:    "tcp_connection_dropped_by=SUBJECT on every case where the closing handshake completed",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1", "autobahn-v25.10.1:1.1.6", "autobahn-v25.10.1:7.1.1"},
			AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. MEASURED " +
				"EXTENT (native x86_64 run, 247-case pinned manifest, both roles): server role 123/247 cases, client role " +
				"0/247 cases (server role only; the client role shows zero cases of this direction, which is consistent " +
				"with Java's client waiting for the server). The suite records the same port behaviour two ways: 91 cases " +
				"where it closed promptly and scored 'It is preferred that the server close the TCP connection' with " +
				"behaviorClose FAILED BY CLIENT, and 32 cases where its own drop timer expired first, " +
				"wasServerConnectionDropTimeout=true, wasNotCleanReason='server did not drop TCP connection (in time)' and " +
				"behaviorClose UNCLEAN. 91 + 32 = 123. Those cases are disjoint from the 122 cases of the " +
				"failure-without-a-close-frame record. The extent above is recomputed from the committed per-case report " +
				"bytes by internal/divergencesweep and recorded per case in " +
				"evidence/java/observed-close-divergences.json; the digest manifest over the 1048 pinned files is " +
				"verified before any report is read, and internal/divergencesweep's tests refuse a document that " +
				"disagrees with the reports.",
			AutobahnValue: "port tcp_connection_dropped_by=AUTOBAHN_SUITE; java tcp_connection_dropped_by=SUBJECT",
			Disposition:   "fix-in-port",
			MismatchClass: "rust-defect",
			Rationale: "DIVERGENCE (server does not close the TCP connection): after the WebSocket closing handshake shipped " +
				"Java's server closes the socket and the port's left it to the peer. MEASURED EXTENT (native x86_64 run, " +
				"247-case pinned manifest, both roles): server role 123/247 cases, client role 0/247 cases, split 91 " +
				"prompt-close cases and 32 drop-timeout cases; those cases are disjoint from the 122 of the " +
				"failure-without-a-close-frame record. MISMATCH CLASS rust-defect: RFC 6455 7.1.1 and shipped Java AGREE " +
				"that the server closes first, so the port was short of both and the mismatch originates in the port. " +
				"DISPOSITION fix-in-port: the remedy is a change in the Rust port. There is no tradeoff to weigh — " +
				"closing a socket the port already considers finished RELEASES a resource rather than acquiring one, and " +
				"the difference is a resource-holding one in production, not only a scoring one. The risk review must " +
				"bound is closing before the peer has read the close frame, which Java avoids by flushing first. STATUS " +
				"OF THAT FIX AT THIS APPEND: the role-gated transport close recorded immediately before this record is " +
				"that change — rust/ws-testee/src/io_loop.rs::server_closes_transport fires only on the drained Idle " +
				"path, the port's image of Java's outQueue.isEmpty(), so the flush ordering the risk turns on is the one " +
				"Java has. The two records are NOT the same proposition: that one binds the RFC-divergent " +
				"initiated-close half of Java's gate, which the port ADOPTS; this one binds the ECHO half, where Java and " +
				"the RFC agree and the port was simply short. What is NOT done is the RE-MEASUREMENT — the extent above " +
				"is the 518b77aa build and re-running the Autobahn suite is an owner gate — so this record's per-case " +
				"set stands as the acceptance criterion and no claim is made that the count is now zero. The extent " +
				"above is recomputed from the committed per-case report bytes by internal/divergencesweep and recorded " +
				"per case in evidence/java/observed-close-divergences.json.",
		},

		// ------------------------------------------------------------------
		// drafts/ledger-proposals/divergence-sweep-3.json (DIV-03)
		// delta-7677db91f7b6267d3614468f70abebcb7c119d539297cd58c697e9bc7b7b8dfa
		{
			Subject: "org.java-websocket.closeframe.invalid-utf8-reason-transport-stall",
			RFCRefs: []string{"rfc6455#section-7.1.6", "rfc6455#section-8.1"},
			RFCExpectation: "RFC 6455 8.1 requires an endpoint that receives a Close frame whose reason is not valid UTF-8 to " +
				"fail the WebSocket connection, which under 7.1.6 ends with the TCP connection closed.",
			RFCValue: "connection failed and the TCP connection closed by the receiving endpoint",
			JavaRef:  "org.java_websocket.framing.CloseFrame:isValid",
			JavaObservation: "Shipped Java 1.6.0 rejects the invalid-UTF-8 reason at runtime inside CloseFrame.isValid (the " +
				"rejection already ledgered at behavior-delta sequence 32) and then neither answers the close nor closes " +
				"the socket. Observed on the native x86_64 run as the suite's own close-handshake timer expiring: " +
				"wasCloseHandshakeTimeout=true, wasNotCleanReason='peer did not respond (in time) in closing handshake', " +
				"droppedByMe=true, duration 1001 ms.",
			JavaValue:    "subject neither sends a close frame nor closes TCP; the peer times out and drops",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.5.1"},
			AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. MEASURED " +
				"EXTENT (native x86_64 run, 247-case pinned manifest, both roles): server role 1/247 cases, client role " +
				"0/247 cases. This is the ONLY case in 494 (247 cases times two roles) where the port ends a TCP " +
				"connection that shipped Java leaves open: the port scored resultClose='Connection was properly closed' " +
				"with duration 0 ms, Java scored 'It is preferred that the server close the TCP connection' with " +
				"wasCloseHandshakeTimeout=true. Both subjects' subject_close_code is null, so no close-code divergence " +
				"exists here. The extent above is recomputed from the committed per-case report bytes by " +
				"internal/divergencesweep and recorded per case in " +
				"evidence/java/observed-close-divergences.json; the digest manifest over the 1048 pinned files is " +
				"verified before any report is read, and internal/divergencesweep's tests refuse a document that " +
				"disagrees with the reports.",
			AutobahnValue: "port tcp_connection_dropped_by=SUBJECT, close_handshake_timeout=false; java " +
				"tcp_connection_dropped_by=AUTOBAHN_SUITE, close_handshake_timeout=true",
			Disposition:   "unresolved",
			MismatchClass: "java-quirk",
			Rationale: "DIVERGENCE (invalid-UTF-8 close reason, resulting transport end): shipped Java STALLS — it rejects the " +
				"reason, sends nothing and holds the socket until the peer times out — and the port ends the transport " +
				"immediately. MEASURED EXTENT (native x86_64 run, 247-case pinned manifest, both roles): server role " +
				"1/247 cases, client role 0/247 cases. It is the ONLY case in 494 role-case pairs where the port ends a " +
				"TCP connection that Java leaves open. MECHANISM: this is the failure-without-a-close-frame mechanism " +
				"with the polarity reversed, because the port's reaction to any failure is to drop TCP. MISMATCH CLASS " +
				"java-quirk: RFC 6455 8.1 is DETERMINATE — an endpoint that receives a Close frame whose reason is not " +
				"valid UTF-8 fails the connection, and under 7.1.6 failing it ends with the TCP connection closed — and " +
				"shipped Java is on the other side of it, holding the socket open and sending nothing. The port is the " +
				"side that agrees with the RFC here; the mismatch originates in Java. DISPOSITION unresolved, AND THE " +
				"RULING NEEDED IS NAMED: reproducing Java means reproducing a one-second peer-side timeout by HOLDING a " +
				"socket a peer has already misused, which trades fidelity against a resource-holding safety property; " +
				"the alternative is to keep the port's prompt close and record it as an intentional-correction with the " +
				"difference disclosed. The evidence measures the difference but cannot weigh that tradeoff, so no " +
				"disposition is asserted here. WHAT WOULD SETTLE IT: an owner ruling on whether the port may hold a " +
				"socket open after a rejected close reason in order to match shipped Java. Note the acceptance criterion " +
				"is explicitly NOT 'this case agrees with the port's old behaviour': it is the one case where a fix that " +
				"only adds a close frame would still leave a difference. The extent above is recomputed from the " +
				"committed per-case report bytes by internal/divergencesweep and recorded per case in " +
				"evidence/java/observed-close-divergences.json.",
		},

		// ------------------------------------------------------------------
		// drafts/ledger-proposals/divergence-sweep-4.json (DIV-05)
		// delta-02e2846c025deec4fd7e279956a7b997c6cab42aa57d0e91df2acb4107c4afb8
		{
			Subject: "org.java-websocket.websocketimpl.pending-echo-versus-close-ordering",
			RFCRefs: []string{"rfc6455#section-5.5.1", "rfc6455#section-7.1.7"},
			RFCExpectation: "RFC 6455 5.5.1 lets an endpoint that receives a Close frame finish sending a message already in " +
				"progress before responding with its own Close frame; nothing requires discarding an application message " +
				"already fully received.",
			RFCValue: "an already-complete application message is delivered, then the close is answered",
			JavaRef:  "org.java_websocket.WebSocketImpl:decodeFrames",
			JavaObservation: "Shipped Java 1.6.0 returns the 256 KiB echo and then answers the close with code 1000: on the native " +
				"x86_64 run its received list carries both the 256 KiB message and the follow-up, and remoteCloseCode is " +
				"1000. flushAndClose demands a write of the queued frames before the channel is closed, so the echo is on " +
				"the wire ahead of the close.",
			JavaValue:    "received=[the 256 KiB echo, ...]; subject_close_code=1000",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.1.6"},
			AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. MEASURED " +
				"EXTENT (native x86_64 run, 247-case pinned manifest, both roles): server role 1/247 cases, client role " +
				"1/247 cases. The port's received list is empty and its subject_close_code is null; the suite's own " +
				"verdict text on the port is 'Close was processed before text message could be returned.' against Java's " +
				"'Actual events differ from any expected.'. Autobahn scores this case INFORMATIONAL for BOTH subjects, " +
				"so no behaviour-class gate in this repository can see the difference, and the public corpus has no 256 " +
				"KiB echo-versus-close race. The extent above is recomputed from the committed per-case report bytes by " +
				"internal/divergencesweep and recorded per case in " +
				"evidence/java/observed-close-divergences.json; the digest manifest over the 1048 pinned files is " +
				"verified before any report is read, and internal/divergencesweep's tests refuse a document that " +
				"disagrees with the reports.",
			AutobahnValue: "port received=[] and subject_close_code=null; java received=[256 KiB echo, 'Hello World!'] and " +
				"subject_close_code=1000",
			Disposition:   "fix-in-port",
			MismatchClass: "rust-defect",
			Rationale: "DIVERGENCE (a close overtakes a large pending echo): with a 256 KiB text message followed immediately " +
				"by a Close, shipped Java delivers the echo and answers the close with 1000; the port drops the echo and " +
				"sends no close. MEASURED EXTENT (native x86_64 run, 247-case pinned manifest, both roles): server role " +
				"1/247 cases, client role 1/247 cases. Autobahn scores the case INFORMATIONAL for BOTH subjects, so no " +
				"behaviour-class gate in this repository can see it and the public corpus has no such race. MISMATCH " +
				"CLASS rust-defect: RFC 6455 5.5.1 lets an endpoint finish sending a message already in progress before " +
				"responding, and requires the close to be responded to; nothing in it licenses discarding a message " +
				"already fully received or answering the close with silence. Java and the RFC therefore agree on both " +
				"observables the port missed, and the mismatch originates in the port. DISPOSITION fix-in-port, WITH ITS " +
				"PRECONDITION STATED: this must first be reproduced as a rust/ws-core or rust/ws-driver test, because " +
				"the sweep can show WHAT the suite saw but not which of the two orderings the port's write queue is " +
				"actually taking. The precondition is WORK THE PORT CAN DO rather than a tradeoff only the owner can " +
				"weigh, which is why the disposition is a fix and not unresolved; if the reproduction shows the port " +
				"cannot enqueue the echo without breaking the ordering ledgered at sequence 34, that finding supersedes " +
				"this disposition and the record becomes one for a preserved ordering. It is NOT sequence 34: that " +
				"record is about a FAILURE path's flush and this is a clean close with no protocol violation. SAFETY: " +
				"delivering a message already fully received adds no unbounded buffering — it is already in memory — but " +
				"it extends the window before the socket is released, which review must bound. The extent above is " +
				"recomputed from the committed per-case report bytes by internal/divergencesweep and recorded per case " +
				"in evidence/java/observed-close-divergences.json.",
		},

		// ------------------------------------------------------------------
		// drafts/ledger-proposals/divergence-sweep-5.json (DIV-06)
		// delta-34db0ad7c9378f88a8b9ddd66d76f9d7323c46a13e89ca04bfac51ea6f273830
		{
			Subject: "org.java-websocket.draft6455.server-handshake.response-server-and-date-fields",
			RFCRefs: []string{"rfc6455#section-4.2.2"},
			RFCExpectation: "RFC 6455 4.2.2 fixes the required fields of the 101 response and neither requires nor forbids a " +
				"Server or Date field; field order is not significant.",
			RFCValue: "response fields include Upgrade, Connection and Sec-WebSocket-Accept; others are permitted",
			JavaRef:  "org.java_websocket.drafts.Draft_6455:postProcessHandshakeResponseAsServer",
			JavaObservation: "Shipped Java 1.6.0 puts Server: TooTallNate Java-WebSocket and Date: getServerTime() into the 101 " +
				"response after the Upgrade, Connection and Sec-WebSocket-Accept fields (pinned source lines 449 and " +
				"450), and HandshakedataImpl1 stores fields in a TreeMap ordered by String.CASE_INSENSITIVE_ORDER, so " +
				"the wire order is alphabetical: Connection, Date, Sec-WebSocket-Accept, Server, Upgrade.",
			JavaValue:    "response header names = [Connection, Date, Sec-WebSocket-Accept, Server, Upgrade]",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
			AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. MEASURED " +
				"EXTENT (native x86_64 run, 247-case pinned manifest, both roles): server role 247/247 cases, client " +
				"role 0/247 cases — every single server-role case, with exactly one distinct value pair: the port writes " +
				"[Upgrade, Connection, Sec-WebSocket-Accept] and Java writes [Connection, Date, Sec-WebSocket-Accept, " +
				"Server, Upgrade]. No Autobahn behaviour class and no handshake-exam check in this repository observes " +
				"the response field set; the exam scores the accept/reject decision and the Sec-WebSocket-Accept value. " +
				"The extent above is recomputed from the committed per-case report bytes by internal/divergencesweep " +
				"and recorded per case in evidence/java/observed-close-divergences.json; the digest manifest over the " +
				"1048 pinned files is verified before any report is read, and internal/divergencesweep's tests refuse a " +
				"document that disagrees with the reports.",
			AutobahnValue: "port response header names = [Upgrade, Connection, Sec-WebSocket-Accept]; java = [Connection, Date, " +
				"Sec-WebSocket-Accept, Server, Upgrade]",
			Disposition:   "unresolved",
			MismatchClass: "underspecified-behavior",
			Rationale: "DIVERGENCE (server 101 response fields): the port's response omits the Server and Date fields shipped " +
				"Java adds, and does not sort its field names. MEASURED EXTENT (native x86_64 run, 247-case pinned " +
				"manifest, both roles): server role 247/247 cases, client role 0/247 cases — every single server-role " +
				"case, with exactly one distinct value pair. The port site is " +
				"rust/ws-core/src/handshake/server.rs::accept_response, whose doc comment cites " +
				"postProcessHandshakeResponseAsServer as the authority for the three fields it writes while that same " +
				"method writes five — an incomplete citation of the cited method, which is why no reviewer caught it. " +
				"MISMATCH CLASS underspecified-behavior: RFC 6455 4.2.2 fixes the REQUIRED fields and neither requires " +
				"nor forbids Server or Date, and field order is not significant, so the RFC does not determine this " +
				"observable at all. Java chose five fields in TreeMap order and the port chose three in its own; the " +
				"mismatch originates in the specification's silence, not in a Java departure and not in a port failure " +
				"to reproduce something the RFC settles. DISPOSITION unresolved, AND THE RULING NEEDED IS NAMED: Date " +
				"carries a CLOCK, and adding a clock-bearing field to a core whose whole design property is " +
				"deterministic composition is a tradeoff only the owner can weigh. Two coherent answers exist — add both " +
				"fields and disclose the Date VALUE as nondeterministic, keeping it out of any byte-equality digest; or " +
				"keep the port's three fields and record the omission as an intentional-correction — and the measurement " +
				"cannot choose between them. WHAT IS NOT IN DOUBT, and is the reason this record exists at all: today " +
				"the omission is neither reproduced nor recorded anywhere, and 100 percent of server-role cases carry " +
				"it. SAFETY: two constant-shaped fields would add a bounded number of bytes to a response already " +
				"bounded by the handshake budget. The extent above is recomputed from the committed per-case report " +
				"bytes by internal/divergencesweep and recorded per case in " +
				"evidence/java/observed-close-divergences.json.",
		},

		// ------------------------------------------------------------------
		// drafts/ledger-proposals/divergence-sweep-6.json (DIV-07)
		// delta-64f32dd26e5b0a555b8a69def312ac8305b2579c4a488b91bd35a021cc898674
		{
			Subject: "org.java-websocket.handshake.field-emission-order",
			RFCRefs: []string{"rfc6455#section-4.1"},
			RFCExpectation: "RFC 6455 4.1 lists the fields a client request must carry and does not constrain their order; under " +
				"RFC 7230 the order of differently named header fields is not significant.",
			RFCValue: "request fields include Host, Upgrade, Connection, Sec-WebSocket-Key and Sec-WebSocket-Version, in any " +
				"order",
			JavaRef: "org.java_websocket.handshake.HandshakedataImpl1:put",
			JavaObservation: "Shipped Java 1.6.0 stores handshake fields in a TreeMap ordered by String.CASE_INSENSITIVE_ORDER and " +
				"Draft.createHandshake writes them in that iteration order, so a Java client request emits Connection, " +
				"Host, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade.",
			JavaValue:    "request header names = [Connection, Host, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade]",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
			AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. MEASURED " +
				"EXTENT (native x86_64 run, 247-case pinned manifest, both roles): server role 0/247 cases, client role " +
				"247/247 cases — every single client-role case, with exactly one distinct value pair. The header SET is " +
				"identical on all of them; only the order differs, and the suite accepted every one of the port's " +
				"requests. The suite's own side of the handshake agreed on all 494 case-role pairs, which is what makes " +
				"this a subject difference rather than a harness one. The extent above is recomputed from the committed " +
				"per-case report bytes by internal/divergencesweep and recorded per case in " +
				"evidence/java/observed-close-divergences.json; the digest manifest over the 1048 pinned files is " +
				"verified before any report is read, and internal/divergencesweep's tests refuse a document that " +
				"disagrees with the reports.",
			AutobahnValue: "port request header names = [Host, Upgrade, Connection, Sec-WebSocket-Key, " +
				"Sec-WebSocket-Version]; java = [Connection, Host, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade]",
			Disposition:   "intentional-correction",
			MismatchClass: "underspecified-behavior",
			Rationale: "DIVERGENCE (handshake field emission order): the port emits the same five client-request fields as " +
				"shipped Java in a different order, on every case. MEASURED EXTENT (native x86_64 run, 247-case pinned " +
				"manifest, both roles): server role 0/247 cases, client role 247/247 cases. The header SET is identical " +
				"on all of them; only the order differs, the suite accepted every one of the port's requests, and the " +
				"suite's own side of the handshake agreed on all 494 case-role pairs, which is what makes this a subject " +
				"difference rather than a harness one. MISMATCH CLASS underspecified-behavior: RFC 6455 4.1 lists the " +
				"fields a client request must carry and does not constrain their order, and under RFC 7230 the order of " +
				"differently named header fields is not significant. The RFC does not determine this observable; Java's " +
				"order falls out of a TreeMap under CASE_INSENSITIVE_ORDER and the port's out of a fixed emission " +
				"sequence, so the mismatch originates in the specification's silence. DISPOSITION " +
				"intentional-correction: the port's fixed order is a deliberate deterministic-composition choice and it " +
				"is KEPT, disclosed rather than removed. Unlike the server-response record this one has no tradeoff to " +
				"weigh — ordering changes nothing that is allocated or parsed, no measured behaviour in this run depends " +
				"on it, and there is no clock and no resource involved — so the evidence settles it and the disposition " +
				"is asserted rather than deferred. WHAT THE DISCLOSURE IS FOR: it is an observable byte-level difference " +
				"from the equivalence target on 100 percent of client-role cases, and a peer that digests the raw " +
				"request head would see it. SCOPE: the CLIENT request only. The server response order is a different " +
				"proposition, carried by the server-handshake response-fields record recorded immediately before this " +
				"one, because there the order difference travels with two MISSING fields and a clock. If the owner later " +
				"rules that byte-level handshake fidelity is in scope, this disposition is the thing that would change, " +
				"and it is recorded here so that ruling has something to overturn. The extent above is recomputed from " +
				"the committed per-case report bytes by internal/divergencesweep and recorded per case in " +
				"evidence/java/observed-close-divergences.json.",
		},
	}
}
