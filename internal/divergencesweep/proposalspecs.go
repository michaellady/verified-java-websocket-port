package divergencesweep

import "fmt"

// extent renders a class's measured case counts for a rationale, so the
// digest preimage — and therefore the delta identity — is a function of the
// report bytes rather than of a number somebody typed.
func extent(class ClassDoc) string {
	server, client := class.CaseCounts["server"], class.CaseCounts["client"]
	return fmt.Sprintf("MEASURED EXTENT (native x86_64 run, %d-case pinned manifest, both roles): server role %d/%d cases, client role %d/%d cases",
		ExpectedCaseCount, server, ExpectedCaseCount, client, ExpectedCaseCount)
}

const sweepProvenance = "The extent above is recomputed from the committed per-case report bytes by internal/divergencesweep and recorded per case in " +
	DocumentPath + "; the digest manifest over the 1048 pinned files is verified before any report is read, and " +
	"internal/divergencesweep's tests refuse a document that disagrees with the reports."

// dimensionOf returns one role's measurement of one dimension. It panics on an
// unknown name rather than returning a zero, because a silently zero count in a
// rationale is exactly the defect this whole package exists to catch.
func dimensionOf(document *Document, role, dimension string) DimensionMeas {
	for _, measured := range document.Measurements {
		if measured.SubjectRole != role {
			continue
		}
		for _, entry := range measured.Dimensions {
			if entry.Dimension == dimension {
				return entry
			}
		}
	}
	panic("divergencesweep: no measurement for " + role + "/" + dimension)
}

// javaValueCount counts the cases on one role and dimension whose JAVA value
// renders exactly as the given canonical JSON.
func javaValueCount(document *Document, role, dimension, javaValue string) int {
	total := 0
	for _, pair := range dimensionOf(document, role, dimension).ValuePairs {
		if pair.Java == javaValue {
			total += pair.CaseCount
		}
	}
	return total
}

// proposalSpecs is the ordered draft set. Order fixes the file numbering. Every
// number quoted in a rationale below is read out of the recomputed measurement,
// never written by hand.
func proposalSpecs(document *Document) []Proposal {
	byClass := map[string]ClassDoc{}
	for _, class := range document.Classes {
		byClass[class.ID] = class
	}
	div01 := byClass["DIV-01-fail-without-close-frame"]
	div02 := byClass["DIV-02-server-leaves-tcp-open"]
	div03 := byClass["DIV-03-invalid-utf8-close-reason-tcp-end"]
	div05 := byClass["DIV-05-close-overtakes-a-large-echo"]
	div06 := byClass["DIV-06-server-101-headers"]
	div07 := byClass["DIV-07-client-request-header-order"]

	// Sub-counts quoted in the rationales, all recomputed.
	closeCodeCount := func(role, code string) int {
		return javaValueCount(document, role, "subject_close_code", code)
	}
	distinctJavaReasons := dimensionOf(document, "server", "subject_close_reason").DistinctValuePairCount
	distinctCloseCodes := dimensionOf(document, "server", "subject_close_code").DistinctValuePairCount
	codeDisagreements := dimensionOf(document, "server", "subject_close_code").BothPresentDiffer +
		dimensionOf(document, "client", "subject_close_code").BothPresentDiffer
	reasonDisagreements := dimensionOf(document, "server", "subject_close_reason").BothPresentDiffer +
		dimensionOf(document, "client", "subject_close_reason").BothPresentDiffer
	promptCloseCases := dimensionOf(document, "server", "failed_by_suite").BothPresentDiffer
	dropTimeoutCases := dimensionOf(document, "server", "server_connection_drop_timeout").BothPresentDiffer
	failWithoutCloseServer := div01.CaseCounts["server"]
	roleCasePairs := 2 * ExpectedCaseCount

	return []Proposal{
		{
			Number:      1,
			ClassID:     "DIV-01-fail-without-close-frame",
			Disposition: "unresolved",
			Definition: ProposalDefinition{
				Subject: "org.java-websocket.websocketimpl.failure-close-frame-emission",
				RFCRefs: []string{"rfc6455#section-7.1.7", "rfc6455#section-7.4.1"},
				RFCExpectation: "RFC 6455 7.1.7 requires an endpoint that fails the WebSocket connection to send a Close frame with an appropriate status code " +
					"before closing the TCP connection, unless it has already received one or cannot determine the status.",
				RFCValue: "close_frame_sent_on_failure=true; close_code=an appropriate 7.4.1 code; close_reason=implementation-defined",
				JavaRef:  "org.java_websocket.WebSocketImpl:close",
				JavaObservation: "Shipped Java 1.6.0 answers an InvalidDataException raised by Draft_6455.translateFrame or processFrame by calling " +
					"WebSocketImpl.close(code, message, false), which composes a CloseFrame carrying the exception's close code and its message text, " +
					"sends it, and only then calls flushAndClose. Observed on the native x86_64 run in " +
					fmt.Sprintf("%d distinct close codes and %d distinct ", distinctCloseCodes, distinctJavaReasons) +
					"reason strings, including 'bad rsv RSV1: false RSV2: false RSV3: true', 'more than 125 octets', 'Unknown opcode 3', " +
					"'closecode must not be sent over the wire: 1004' and 'Received text is no valid utf8 string!'.",
				JavaValue:    "subject_close_code in {1000,1002,1007}; subject_close_reason=the InvalidDataException message; tcp_end=after the closing handshake",
				AutobahnRefs: []string{"autobahn-v25.10.1:2.5", "autobahn-v25.10.1:3.1", "autobahn-v25.10.1:6.3.1", "autobahn-v25.10.1:7.1.3"},
				AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa (ws-testee), same host and same " +
					"247-case manifest as the Java baseline. " + extent(div01) + ". On every case in that set the port's subject_close_code is null " +
					fmt.Sprintf("(no close frame reached the suite) where Java's is 1007 (%d server / %d client), 1002 (%d server / %d client) or 1000 (%d server / %d client). ",
						closeCodeCount("server", "1007"), closeCodeCount("client", "1007"),
						closeCodeCount("server", "1002"), closeCodeCount("client", "1002"),
						closeCodeCount("server", "1000"), closeCodeCount("client", "1000")) +
					"On every case where the port DID send a close frame the code and the reason equal Java's: " +
					fmt.Sprintf("%d code disagreements and %d reason disagreements ", codeDisagreements, reasonDisagreements) +
					"among the cases where both spoke. The Autobahn behaviour class hides this: both subjects score OK on most of the set. " +
					sweepProvenance,
				AutobahnValue: "port subject_close_code=null, subject_close_reason=null; java subject_close_code in {1000,1002,1007} with 32 distinct reason strings",
				Rationale: "DIVERGENCE (failure without a Close frame): shipped Java answers a protocol failure with a Close frame carrying the failing " +
					"exception's code and message and then closes; the port's Autobahn adapter drops the TCP connection with nothing on the wire. " +
					"RFC 6455 7.1.7 and shipped Java AGREE here, so this is not an RFC-versus-Java question: the port is short of both. " +
					extent(div01) + ". RECOMMENDATION: FIX IN THE PORT, not ledger as a preserved behaviour. The equivalence target is shipped Java " +
					"1.6.0 quirks included, and a peer that logs or branches on the close code and reason sees a different program. A fix already " +
					"exists on branch claude/post-failure (commit 77d8c23, 'ws-testee: answer a protocol violation the way shipped Java does'), which " +
					"is NOT in mainline at the sweep's head; this record's per-case set is the acceptance criterion that fix should be measured against " +
					"on a re-run, and until such a re-run exists the record stays unresolved. SAFETY: emitting the close frame adds one bounded write " +
					"on a path that already terminates the connection; no unbounded buffering and no new panic path. " + sweepProvenance,
			},
		},
		{
			Number:      2,
			ClassID:     "DIV-02-server-leaves-tcp-open",
			Disposition: "unresolved",
			Definition: ProposalDefinition{
				Subject: "org.java-websocket.websocketimpl.server-tcp-close-after-close-handshake",
				RFCRefs: []string{"rfc6455#section-7.1.1"},
				RFCExpectation: "RFC 6455 7.1.1 says the server closes the underlying TCP connection first, and the client should wait for the server to " +
					"do so; an endpoint may close it if it has not been closed after a reasonable delay.",
				RFCValue: "tcp_closed_by=server, once the closing handshake is complete",
				JavaRef:  "org.java_websocket.WebSocketImpl:closeConnection",
				JavaObservation: "Shipped Java 1.6.0 finishes the closing handshake through flushAndClose, whose write demand flushes the pending close " +
					"frame, after which closeConnection cancels the selection key and calls channel.close(). The server end of the socket therefore goes " +
					"away without the client acting. Observed on the native x86_64 run as the suite recording droppedByMe=false on the Java server leg.",
				JavaValue:    "tcp_connection_dropped_by=SUBJECT on every case where the closing handshake completed",
				AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1", "autobahn-v25.10.1:1.1.6", "autobahn-v25.10.1:7.1.1"},
				AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. " + extent(div02) + " (server role only; " +
					"the client role shows zero cases of this direction, which is consistent with Java's client waiting for the server). The suite " +
					"records the same port behaviour two ways: " + fmt.Sprintf("%d", promptCloseCases) + " cases where it closed promptly and scored 'It is " +
					"preferred that the server close the TCP connection' with behaviorClose FAILED BY CLIENT, and " + fmt.Sprintf("%d", dropTimeoutCases) +
					" cases where its own drop timer expired first, wasServerConnectionDropTimeout=true, wasNotCleanReason='server did not drop TCP " +
					"connection (in time)' and behaviorClose UNCLEAN. " +
					fmt.Sprintf("%d + %d = %d. Those cases are disjoint from the %d cases of the failure-without-a-close-frame record. ",
						promptCloseCases, dropTimeoutCases, promptCloseCases+dropTimeoutCases, failWithoutCloseServer) + sweepProvenance,
				AutobahnValue: "port tcp_connection_dropped_by=AUTOBAHN_SUITE; java tcp_connection_dropped_by=SUBJECT",
				Rationale: "DIVERGENCE (server does not close the TCP connection): after the WebSocket closing handshake shipped Java's server closes the " +
					"socket and the port's leaves it to the peer. RFC 6455 7.1.1 and shipped Java AGREE, so the port is short of both. " + extent(div02) +
					fmt.Sprintf(", split %d prompt-close cases and %d drop-timeout cases. ", promptCloseCases, dropTimeoutCases) +
					"RECOMMENDATION: FIX IN THE PORT (this is the divergence already queued as " +
					"P2(b) in .claude/GOAL-LOOP.md). It is a divergence from the equivalence target AND a resource-holding difference: a production peer " +
					"sees sockets the shipped implementation would have released. The Java site to reproduce is WebSocketImpl.flushAndClose followed by " +
					"closeConnection, gated on the server role by the fact that Java's client waits instead. SAFETY: closing a socket the port already " +
					"considers finished releases a resource rather than acquiring one; the risk to check in review is closing before the peer has read " +
					"the close frame, which Java avoids by flushing first. " + sweepProvenance,
			},
		},
		{
			Number:      3,
			ClassID:     "DIV-03-invalid-utf8-close-reason-tcp-end",
			Disposition: "unresolved",
			Definition: ProposalDefinition{
				Subject: "org.java-websocket.closeframe.invalid-utf8-reason-transport-stall",
				RFCRefs: []string{"rfc6455#section-7.1.6", "rfc6455#section-8.1"},
				RFCExpectation: "RFC 6455 8.1 requires an endpoint that receives a Close frame whose reason is not valid UTF-8 to fail the WebSocket " +
					"connection, which under 7.1.6 ends with the TCP connection closed.",
				RFCValue: "connection failed and the TCP connection closed by the receiving endpoint",
				JavaRef:  "org.java_websocket.framing.CloseFrame:isValid",
				JavaObservation: "Shipped Java 1.6.0 rejects the invalid-UTF-8 reason at runtime inside CloseFrame.isValid (the rejection already ledgered " +
					"at behavior-delta sequence 32) and then neither answers the close nor closes the socket. Observed on the native x86_64 run as the " +
					"suite's own close-handshake timer expiring: wasCloseHandshakeTimeout=true, wasNotCleanReason='peer did not respond (in time) in " +
					"closing handshake', droppedByMe=true, duration 1001 ms.",
				JavaValue:    "subject neither sends a close frame nor closes TCP; the peer times out and drops",
				AutobahnRefs: []string{"autobahn-v25.10.1:7.5.1"},
				AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. " + extent(div03) + ". This is the ONLY " +
					fmt.Sprintf("case in %d (%d cases times two roles) where the port ends a TCP connection that shipped Java leaves open: the port scored ",
						roleCasePairs, ExpectedCaseCount) +
					"resultClose='Connection was properly closed' with duration 0 ms, Java scored 'It is preferred that the server close the TCP " +
					"connection' with wasCloseHandshakeTimeout=true. Both subjects' subject_close_code is null, so no close-code divergence exists here. " +
					sweepProvenance,
				AutobahnValue: "port tcp_connection_dropped_by=SUBJECT, close_handshake_timeout=false; java tcp_connection_dropped_by=AUTOBAHN_SUITE, close_handshake_timeout=true",
				Rationale: "DIVERGENCE (invalid-UTF-8 close reason, resulting transport end): shipped Java stalls — it rejects the reason, sends nothing " +
					"and holds the socket until the peer times out — and the port ends the transport immediately. " + extent(div03) + ". MECHANISM: this " +
					"is the failure-without-a-close-frame mechanism with the polarity reversed, because the port's reaction to any failure is to drop " +
					"TCP. RECOMMENDATION: FIX IN THE PORT, as part of the failure-close-frame fix, and NOT ledgered as an intentional correction. It is " +
					"recorded separately because it is the one case where a fix that only adds a close frame would still leave a difference: shipped " +
					"Java's behaviour here is to send nothing AND hold the socket, so reproducing it means reproducing the stall. Its acceptance " +
					"criterion is therefore explicitly NOT 'this case now agrees with the port's old behaviour'. If the owner rules that reproducing a " +
					"1-second peer-side timeout is not worth reproducing, this becomes LEDGER AS INTENTIONAL CORRECTION instead, with the port's prompt " +
					"close disclosed. SAFETY: the port's current behaviour is the safe one; the risk of matching Java here is holding a socket a peer " +
					"has already misused, which is why this needs an owner ruling rather than a silent fix. " + sweepProvenance,
			},
		},
		{
			Number:      4,
			ClassID:     "DIV-05-close-overtakes-a-large-echo",
			Disposition: "unresolved",
			Definition: ProposalDefinition{
				Subject: "org.java-websocket.websocketimpl.pending-echo-versus-close-ordering",
				RFCRefs: []string{"rfc6455#section-5.5.1", "rfc6455#section-7.1.7"},
				RFCExpectation: "RFC 6455 5.5.1 lets an endpoint that receives a Close frame finish sending a message already in progress before " +
					"responding with its own Close frame; nothing requires discarding an application message already fully received.",
				RFCValue: "an already-complete application message is delivered, then the close is answered",
				JavaRef:  "org.java_websocket.WebSocketImpl:decodeFrames",
				JavaObservation: "Shipped Java 1.6.0 returns the 256 KiB echo and then answers the close with code 1000: on the native x86_64 run its " +
					"received list carries both the 256 KiB message and the follow-up, and remoteCloseCode is 1000. flushAndClose demands a write of the " +
					"queued frames before the channel is closed, so the echo is on the wire ahead of the close.",
				JavaValue:    "received=[the 256 KiB echo, ...]; subject_close_code=1000",
				AutobahnRefs: []string{"autobahn-v25.10.1:7.1.6"},
				AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. " + extent(div05) + ". The port's " +
					"received list is empty and its subject_close_code is null; the suite's own verdict text on the port is 'Close was processed before " +
					"text message could be returned.' against Java's 'Actual events differ from any expected.'. Autobahn scores this case INFORMATIONAL " +
					"for BOTH subjects, so no behaviour-class gate in this repository can see the difference, and the public corpus has no 256 KiB " +
					"echo-versus-close race. " + sweepProvenance,
				AutobahnValue: "port received=[] and subject_close_code=null; java received=[256 KiB echo, 'Hello World!'] and subject_close_code=1000",
				Rationale: "DIVERGENCE (a close overtakes a large pending echo): with a 256 KiB text message followed immediately by a Close, shipped Java " +
					"delivers the echo and answers the close; the port drops the echo and sends no close. " + extent(div05) + ". RECOMMENDATION: FIX IN " +
					"THE PORT, with a reproduction as its precondition: this must first be reproduced as a rust/ws-core or rust/ws-driver test, because " +
					"the sweep can only show WHAT the suite saw, not which of the two orderings the port's write queue is actually taking. If the " +
					"reproduction shows the port cannot enqueue the echo without breaking the ordering ledgered at sequence 34, this becomes a ledger " +
					"record for a preserved ordering instead, and the record's disposition should be revisited then. It is NOT sequence 34: that record " +
					"is about a FAILURE path's flush and this is a clean close with no protocol violation. SAFETY: delivering a message already fully " +
					"received before answering a close adds no unbounded buffering — the message is already in memory — but it does extend the window " +
					"before the socket is released, which review must bound. " + sweepProvenance,
			},
		},
		{
			Number:      5,
			ClassID:     "DIV-06-server-101-headers",
			Disposition: "unresolved",
			Definition: ProposalDefinition{
				Subject: "org.java-websocket.draft6455.server-handshake.response-server-and-date-fields",
				RFCRefs: []string{"rfc6455#section-4.2.2"},
				RFCExpectation: "RFC 6455 4.2.2 fixes the required fields of the 101 response and neither requires nor forbids a Server or Date field; " +
					"field order is not significant.",
				RFCValue: "response fields include Upgrade, Connection and Sec-WebSocket-Accept; others are permitted",
				JavaRef:  "org.java_websocket.drafts.Draft_6455:postProcessHandshakeResponseAsServer",
				JavaObservation: "Shipped Java 1.6.0 puts Server: TooTallNate Java-WebSocket and Date: getServerTime() into the 101 response after the " +
					"Upgrade, Connection and Sec-WebSocket-Accept fields (pinned source lines 449 and 450), and HandshakedataImpl1 stores fields in a " +
					"TreeMap ordered by String.CASE_INSENSITIVE_ORDER, so the wire order is alphabetical: Connection, Date, Sec-WebSocket-Accept, " +
					"Server, Upgrade.",
				JavaValue:    "response header names = [Connection, Date, Sec-WebSocket-Accept, Server, Upgrade]",
				AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
				AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. " + extent(div06) + " — every single " +
					"server-role case, with exactly one distinct value pair: the port writes [Upgrade, Connection, Sec-WebSocket-Accept] and Java writes " +
					"[Connection, Date, Sec-WebSocket-Accept, Server, Upgrade]. No Autobahn behaviour class and no handshake-exam check in this " +
					"repository observes the response field set; the exam scores the accept/reject decision and the Sec-WebSocket-Accept value. " + sweepProvenance,
				AutobahnValue: "port response header names = [Upgrade, Connection, Sec-WebSocket-Accept]; java = [Connection, Date, Sec-WebSocket-Accept, Server, Upgrade]",
				Rationale: "DIVERGENCE (server 101 response fields): the port's response omits the Server and Date fields shipped Java adds and does not " +
					"sort its field names. " + extent(div06) + ". The port site is rust/ws-core/src/handshake/server.rs::accept_response, whose doc " +
					"comment cites postProcessHandshakeResponseAsServer as the authority for the three fields it writes while that same method writes " +
					"five — an incomplete citation of the cited method, which is why no reviewer caught it. RECOMMENDATION: FIX IN THE PORT. Date " +
					"carries a clock and so cannot be reproduced byte-for-byte; that is a reason to disclose the field's VALUE as nondeterministic (and " +
					"to keep it out of any byte-equality digest), not a reason to omit the field. If the owner rules that adding a clock-bearing field " +
					"to a deterministic core is unacceptable, the alternative is LEDGER AS INTENTIONAL CORRECTION with the omission disclosed — but the " +
					"omission must then be disclosed, because today it is neither reproduced nor recorded anywhere. SAFETY: two constant-shaped fields " +
					"add a bounded number of bytes to a response already bounded by the handshake budget. " + sweepProvenance,
			},
		},
		{
			Number:      6,
			ClassID:     "DIV-07-client-request-header-order",
			Disposition: "unresolved",
			Definition: ProposalDefinition{
				Subject: "org.java-websocket.handshake.field-emission-order",
				RFCRefs: []string{"rfc6455#section-4.1"},
				RFCExpectation: "RFC 6455 4.1 lists the fields a client request must carry and does not constrain their order; under RFC 7230 the order " +
					"of differently named header fields is not significant.",
				RFCValue:        "request fields include Host, Upgrade, Connection, Sec-WebSocket-Key and Sec-WebSocket-Version, in any order",
				JavaRef:         "org.java_websocket.handshake.HandshakedataImpl1:put",
				JavaObservation: "Shipped Java 1.6.0 stores handshake fields in a TreeMap ordered by String.CASE_INSENSITIVE_ORDER and Draft.createHandshake writes them in that iteration order, so a Java client request emits Connection, Host, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade.",
				JavaValue:       "request header names = [Connection, Host, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade]",
				AutobahnRefs:    []string{"autobahn-v25.10.1:1.1.1"},
				AutobahnResult: "EXECUTED, native x86_64 provenance run us019-prov-20260828T183623Z, port build 518b77aa. " + extent(div07) + " — every single " +
					"client-role case, with exactly one distinct value pair. The header SET is identical on all of them; only the order differs, and the " +
					"suite accepted every one of the port's requests. " + fmt.Sprintf("The suite's own side of the handshake agreed on all %d case-role pairs, which is ", roleCasePairs) +
					"what makes this a subject difference rather than a harness one. " + sweepProvenance,
				AutobahnValue: "port request header names = [Host, Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Version]; java = [Connection, Host, Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade]",
				Rationale: "DIVERGENCE (handshake field emission order): the port emits the same five client-request fields as shipped Java in a different " +
					"order, on every case. " + extent(div07) + ". RECOMMENDATION: LEDGER AS AN INTENTIONAL CORRECTION, not fixed and not left silent. " +
					"Field order is not semantically significant for distinct field names, no measured behaviour in this run depends on it, and the port's " +
					"fixed order is a deliberate deterministic-composition choice rather than an oversight — but it is an observable byte-level difference " +
					"from the equivalence target on 100 percent of cases, and a peer that digests the raw request head would see it, so it must be " +
					"disclosed. This record's scope is the CLIENT request only: the server response order is a different proposition, carried by the " +
					"server-handshake response-fields record, because there the order difference travels with two missing fields. If the owner rules " +
					"that byte-level handshake fidelity is in scope, this becomes FIX IN THE PORT alongside that record. SAFETY: none; ordering does not " +
					"change what is allocated or parsed. " + sweepProvenance,
			},
		},
	}
}
