package deltaledger

// gapClosureDefinitions closes the three behavior-delta-ledger gaps the
// US-010/US-011/US-016 acceptance audit named (drafts/acceptance/ROLLUP.md,
// gaps G3c, G3d and G3e). Appended AFTER every existing definition so the
// committed 35-record hash-chain prefix is unchanged.
//
//   - G3c (blocks US-010): the CLIENT-handshake direction had ZERO records.
//     All sixteen original handshake records cite `client_request`-direction
//     cases, which are the SERVER slice. The six rows that
//     evidence/us005-handshake-live-mapping.json records as
//     `divergent: true` on the `server_response` direction — the direction a
//     client parses — had no record at all. The six records below are those
//     rows, one each.
//
//   - G3d: the smuggling-shaped seeds (`content-length`,
//     `transfer-encoding`) were covered only by the general lenient-parse
//     class. Two records below ledger them individually.
//
//   - G3e: the pre-open poison strengthening, disclosed in
//     protected/e4-autopong-eof-receipt.json honesty note 3 but never
//     ledgered. One record below.
//
// G3f is deliberately absent: the rejected-close-transition divergence
// already has delta-9dd3ab86744b6c2dc69a0452ea51ec26c5d170dc50e15b923bcb507af8a0b1ae
// at sequence 35 (closeTransitionDefinitions), verified present and correct.
func gapClosureDefinitions() []Definition {
	definitions := clientHandshakeDefinitions()
	definitions = append(definitions, messageFramingHeaderDefinitions()...)
	definitions = append(definitions, preOpenRefusalDefinitions()...)
	definitions = append(definitions, rsvRejectionStateDefinitions()...)
	return definitions
}

// rsvRejectionStateDefinitions ledger the proposition the cross-plane defect
// audit found uncovered: "a reserved-bit protocol rejection leaves ReadyState
// OPEN" (drafts/codex-us020-defect-crosscheck.md section 8).
//
// The audit reported this tentatively ("does not appear to cover") and asked
// for a saturating check. That check was done over all 35 committed records
// and the audit is CORRECT: sequence 20 scopes itself to the rejection SITE
// and explicitly states that the RFC and Java agree on the 1002 verdict, so it
// never reaches the resulting ReadyState; sequence 35 is a locally initiated
// close on a different scenario. No other record mentions RSV, ReadyState or
// final_state at all.
//
// The record below records one thing the audit did not have, and it changes
// the shape of the finding: shipped Java's TWO entry points disagree with each
// other here, exactly as they do for the sequence-35 rejected-close record.
// The library path closes; the adapter path does not. Our port matches the
// adapter path, which is what the live corpus measures — and the Codex plane's
// RFC-ranked "closed" therefore coincides with what shipped
// WebSocketImpl.decodeFrames actually does, rather than opposing Java outright.
func rsvRejectionStateDefinitions() []Definition {
	return []Definition{
		{
			Subject: "org.java-websocket.draft6455.framing.rsv-rejection-readystate",
			RFCRefs: []string{"rfc6455#section-5.2", "rfc6455#section-7.1.7"},
			RFCExpectation: "RFC 6455 section 5.2 requires RSV1, RSV2 and RSV3 to be 0 unless an extension has been " +
				"negotiated that defines meanings for them, and requires an endpoint that receives a nonzero RSV bit with " +
				"no such extension to _Fail the WebSocket Connection_. Section 7.1.7 defines Failing the WebSocket " +
				"Connection as sending a Close frame where appropriate and then closing the connection, after which the " +
				"endpoint MUST NOT process further data. An endpoint that has failed the connection is therefore no " +
				"longer in the OPEN ready state.",
			RFCValue: "closed: failing the WebSocket connection takes the endpoint out of OPEN",
			JavaRef:  "org.java_websocket.extensions.DefaultExtension:isFrameValid",
			JavaObservation: "The rejection itself is unambiguous and live-confirmed: DefaultExtension.isFrameValid " +
				"(DefaultExtension.java:62-66) throws InvalidFrameException when any RSV bit is set, and " +
				"InvalidFrameException's constructor passes CloseFrame.PROTOCOL_ERROR " +
				"(exceptions/InvalidFrameException.java:45-47), i.e. 1002. The live pinned runtime recorded exactly that " +
				"for us005.pub.0005, down to the message text: error.code JAVA_INVALID_DATA, error.close_code 1002, " +
				"detail \"bad rsv RSV1: false RSV2: true RSV3: false\" " +
				"(protected/us005-corpora/live/public/transcript.jsonl). WHAT THE RESULTING STATE IS DEPENDS ON WHICH " +
				"JAVA ENTRY POINT RUNS, and the two shipped entry points disagree — the same structure the " +
				"rejected-local-close record at sequence 35 documents. (A) The shipped library path " +
				"WebSocketImpl.decodeFrames (WebSocketImpl.java:390-417) wraps draft.translateFrame in a try block whose " +
				"InvalidDataException arm logs, notifies onWebsocketError and then calls close(e) " +
				"(WebSocketImpl.java:404-407). Through this path the connection DOES leave OPEN. (B) The pinned oracle " +
				"adapter never calls decodeFrames: OracleEngine.input calls draft.translateFrame(input) directly " +
				"(java-oracle/src/main/java/OracleEngine.java:343), so the InvalidFrameException propagates out of the " +
				"step loop to the adapter's top-level catch (OracleEngine.java:95-97), which records JAVA_INVALID_DATA " +
				"with the close code and never reaches WebSocketImpl.close. The recorded final_state therefore stays " +
				"open, with zero transitions, zero frames and zero actions. THE LIVE RECORDING RESOLVES WHICH PATH THE " +
				"CORPUS MEASURES: path (B). Read from the real transcripts at this branch, our Rust and the live pinned " +
				"Java agree field for field on us005.pub.0005 — final_state open, no transitions, consumed_bytes 9 = 9, " +
				"input_bytes 9 = 9, frames 0, actions 0, close_code 1002 — and the 74/74 public evaluate is exit 0.",
			JavaValue: "entry-point-dependent: WebSocketImpl.decodeFrames closes on the caught InvalidDataException " +
				"(WebSocketImpl.java:404-407) while the adapter's direct translateFrame call lets the same exception " +
				"propagate, and the live-recorded ready state stays open",
			AutobahnRefs: []string{"autobahn-v25.10.1:3.1", "autobahn-v25.10.1:3.2"},
			Rationale: "DIVERGENCE (reserved-bit rejection, resulting ReadyState): the RFC requires failing the " +
				"connection, which takes the endpoint out of OPEN; the port leaves it OPEN because that is what the live " +
				"pinned Java oracle records. This proposition was UNLEDGERED before this record, which the cross-plane " +
				"defect audit flagged (drafts/codex-us020-defect-crosscheck.md section 8) and a saturating re-check of " +
				"all 35 prior records confirmed: sequence 20 " +
				"(framing.post-payload-rejection-site) scopes itself to the rejection SITE and asserts that RFC and Java " +
				"AGREE on the 1002 verdict, so it never reaches the state question, and sequence 35 is a locally " +
				"initiated close on us005.pub.0000. OPPOSING AUTHORITY, verified rather than paraphrased: the Codex " +
				"plane at commit df6aa20 ranks the RFC above Java at this exact pointer. Its " +
				"evidence/oracle-hierarchy.json cell for us005.pub.0005 /final_state reads authority " +
				"rfc6455.section-5-2, rank 1, expected_sha256 " +
				"sha256:02e31f51aa8b1b6a622c4f7c30fab328d711cad4c9da74b9965ada8aa15d9df2 — which is the SHA-256 of the " +
				"JSON-encoded string \"closed\" (with quotes), not of the bare six bytes. Its own " +
				"evidence/java/behavior-delta-ledger.json sequence 1 (delta.us005.pub.0005.final_state) classifies " +
				"Java's open as java_quirk with resolution retained_java_quirk, and its sequence 2 " +
				"(delta.us005.pub.0005.transitions) does the same for the transitions pointer under " +
				"rfc6455.section-7-1-7. Both planes are internally self-consistent, so this is a normative choice, not " +
				"a defect on either side — but the choice is now recorded on this side too. NOTE ON WHAT THE CODEX " +
				"READING ACTUALLY OPPOSES: because of the two-entry-point split above, their RFC-ranked closed " +
				"coincides with what shipped WebSocketImpl.decodeFrames does; the reading they decline to follow is the " +
				"ADAPTER's, which is the one our corpus measures. POINTER SCOPE: this single record covers both the " +
				"final_state and the transitions observables, which are one proposition here (no close transition " +
				"occurred, so the state never left open); the Codex ledger splits them into two pointer-shaped records. " +
				"WS_CORE SITE: rust/ws-core/src/framing.rs post-payload RSV checks produce the typed rejection, and " +
				"rust/ws-core/src/connection.rs does NOT transition on it; pinned by " +
				"rust/ws-core/tests/frame_codec.rs::reserved_bits_reject_1002_only_after_the_full_frame; seeds " +
				"rust/ws-core/fuzz-seeds/us012/rsv1.hex, rsv2.hex, rsv3.hex. SAFETY: staying OPEN after a refused frame " +
				"is not a permissive choice at the wire — the frame is rejected, nothing is delivered, no byte is " +
				"written, and the consumed payload is still bounded by the control-payload and configured frame-size " +
				"gates under forbid(unsafe_code). An embedding layer that wants RFC 7.1.7 failure semantics can drive " +
				"the close from the returned typed failure, exactly as the shipped library's own decodeFrames does. " +
				"DISPOSITION NOTE: 'unresolved' is the frozen 1.0.0 vocabulary's only retained-divergence term; the " +
				"divergence is deliberately retained on live evidence, not left unexamined." + ownerDecision,
		},
	}
}

// clientMappingEvidence is the shared evidence citation for the client
// (`server_response`) direction. It states the execution scope explicitly
// rather than implying a live corpus execution that does not exist: NONE of
// the ten `server_response` cases in corpora/handshake/cases.jsonl exercises
// any of these six keys — those ten carry HS_STATUS_NOT_101,
// HS_MISSING_ACCEPT, HS_ACCEPT_MISMATCH and HS_MISSING_UPGRADE, and every one
// of them is a NON-divergent row. The Java behavior here is therefore the
// source-read mapping row plus the byte-level client seed replay, and it is
// recorded as exactly that.
const clientMappingEvidence = "FIDELITY EVIDENCE: mapping-row direction=server_response key=%KEY% of " +
	"evidence/us005-handshake-live-mapping.json (divergent=true), rendered from " +
	"internal/corpora.HandshakeVerdictMapping and pinned byte-identical to that rendering by " +
	"internal/corpora TestHandshakeLiveMappingEvidenceDocument; source basis read in the digest-pinned " +
	"quarantined Java-WebSocket 1.6.0 tree (revision da3cf2a777aed862f2f5b5cf060cae7969958667, jar sha256 " +
	"eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f). EXECUTION SCOPE, stated rather than " +
	"implied: no live-executed corpus case backs this row. None of the ten server_response cases in " +
	"corpora/handshake/cases.jsonl exercises this key (they carry HS_STATUS_NOT_101, HS_MISSING_ACCEPT, " +
	"HS_ACCEPT_MISMATCH and HS_MISSING_UPGRADE, all non-divergent), so unlike the sixteen server-slice " +
	"handshake records this one cites no us005.hs.NNNN case."

// clientHandshakeSafety is the shared safety note for the client direction.
const clientHandshakeSafety = " SAFETY: the client response path is bounded by the same configured handshake " +
	"budgets as the server path — ClientHandshake::consume routes every transport chunk through " +
	"HeadAccumulator::push (rust/ws-core/src/handshake/http.rs), which checks the total-byte, header-line and " +
	"header-count budgets BEFORE it buffers each byte and returns ClientHandshakeOutcome::LimitExceeded naming " +
	"the first refused budget — under forbid(unsafe_code). Emulating Java's missing checks introduces no " +
	"unchecked allocation and no panic path."

// clientHandshakeDefinition builds one client-direction record. Unlike the
// server-side helper, the Java value is NOT "accept": the mapping records
// these rows as `conditional`, because the check simply does not exist in the
// Java client path and the outcome is decided by the checks that do run.
func clientHandshakeDefinition(key, family, subject, javaRef, rfcExpectation, javaObservation, seed, rationale string, rfcRefs []string) Definition {
	return Definition{
		Subject:        subject,
		RFCRefs:        rfcRefs,
		RFCExpectation: rfcExpectation,
		RFCValue: "reject: refuse the server's opening handshake for this reason and fail the WebSocket " +
			"connection (the connection never reaches Open)",
		JavaRef: javaRef,
		JavaObservation: javaObservation + " " +
			replaceKey(clientMappingEvidence, key) + " (family " + family + ").",
		JavaValue: "conditional: the check does not exist in the Java client path, so the observable is decided " +
			"entirely by the checks that DO run over the same bytes — translateHandshakeHttpClient's literal \"101\" " +
			"status token and HTTP-version comparison (Draft.java:164-180), basicAccept's Upgrade/Connection gate " +
			"(Draft.java:188-191) and the literal Sec-WebSocket-Accept equality (Draft_6455.java:306-343)",
		AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
		Rationale: "DIVERGENCE (client handshake, " + family + "; mapping-row direction=server_response key=" + key +
			"): " + rationale +
			" WS_CORE SITE: rust/ws-core/src/handshake/client.rs ClientHandshake::consume implements the shipped Java " +
			"client predicate over the shared parser in rust/ws-core/src/handshake/http.rs (parse_java_head), and its " +
			"module doc names this stripped check explicitly. Pinned by " +
			"rust/ws-core/tests/handshake_seeds.rs::us010_client_seeds_replay_with_java_model_expectations, seed " +
			"rust/ws-core/fuzz-seeds/us010/" + seed + ".hex." +
			clientHandshakeSafety + ownerDecision,
	}
}

func replaceKey(template, key string) string {
	out := ""
	for i := 0; i < len(template); {
		if i+5 <= len(template) && template[i:i+5] == "%KEY%" {
			out += key
			i += 5
			continue
		}
		out += string(template[i])
		i++
	}
	return out
}

// clientHandshakeDefinitions are the six divergent `server_response` rows —
// the whole client-handshake direction that G3c found unledgered.
func clientHandshakeDefinitions() []Definition {
	readLineRef := "org.java_websocket.drafts.Draft:readLine"
	translateHTTP := "org.java_websocket.drafts.Draft:translateHandshakeHttp"
	section41 := []string{"rfc6455#section-4.1", "rfc6455#section-4.2.2"}
	section104 := []string{"rfc6455#section-10.4"}

	noLimits := "Java-WebSocket 1.6.0 has no handshake byte, header-count or header-line limit on EITHER " +
		"direction: translateHandshakeHttp reads unboundedly (Draft.java:70-132) and the client read loop grows " +
		"tmpHandshakeBytes without a ceiling (WebSocketImpl.java:370-387 reallocates to the exception's preferred " +
		"size, or to capacity+16 when it is zero, and never refuses)."

	return []Definition{
		clientHandshakeDefinition("HS_LIMIT_TOTAL_BYTES", "limit-total-bytes",
			"org.java-websocket.draft6455.client-handshake.limit-total-bytes", translateHTTP,
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake "+
				"inputs before committing resources; the RFC-derived model rejects an over-budget server response "+
				"(HS_LIMIT_TOTAL_BYTES).",
			noLimits+" The over-budget response is therefore parsed in full and its acceptance is decided by "+
				"basicAccept and the accept-value comparison alone.",
			"total-limit",
			"the RFC-derived model rejects the over-budget server response; the pinned Java client has no total-byte "+
				"limit and lets the remaining checks decide. ws_core does NOT emulate the unbounded growth: it retains "+
				"the CONFIGURED total-byte budget as a hard safety ceiling (JAVA_FAITHFUL_PLUS_SAFE — the owner "+
				"amendment expressly does not relax checked config limits), and within that ceiling the parser "+
				"reproduces Java's no-limit behavior. The seed replay runs at HandshakeLimits::hard_ceilings, where the "+
				"seed is an incomplete head rather than a limit refusal, exactly as Java records it. HONEST GAP, "+
				"recorded rather than glossed: the CLIENT path has no configured-budget refusal test of its own; the "+
				"only committed budget-refusal pin is the server's "+
				"(rust/ws-core/tests/handshake_server.rs::configured_budgets_refuse_with_the_named_limit), and the "+
				"client shares the same HeadAccumulator by construction, not by test.",
			section104),
		clientHandshakeDefinition("HS_LIMIT_HEADER_COUNT", "limit-header-count",
			"org.java-websocket.draft6455.client-handshake.limit-header-count", translateHTTP,
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake "+
				"inputs; the RFC-derived model rejects an over-count server response (HS_LIMIT_HEADER_COUNT).",
			noLimits+" The header loop in translateHandshakeHttp (Draft.java:113-127) has no count bound, so extra "+
				"response headers are simply stored and ignored.",
			"count-limit",
			"the RFC-derived model rejects the over-count server response; the pinned Java client accepts it, because "+
				"unknown extra headers are stored and never consulted. This is the sharpest of the three limit rows: "+
				"the recorded client seed replay ACCEPTS (`extra headers are ignored and Java has no count limit`), so "+
				"the divergence is an accept-vs-reject disagreement, not merely a difference in which check fires "+
				"first. ws_core retains the CONFIGURED header-count budget as the safety ceiling "+
				"(JAVA_FAITHFUL_PLUS_SAFE) and reproduces the accept within it.",
			section104),
		clientHandshakeDefinition("HS_LIMIT_HEADER_LINE_BYTES", "limit-header-line",
			"org.java-websocket.draft6455.client-handshake.limit-header-line", readLineRef,
			"RFC 6455 section 10.4 expects implementations to enforce implementation-specific limits on handshake "+
				"inputs; the RFC-derived model rejects an over-length response header line "+
				"(HS_LIMIT_HEADER_LINE_BYTES).",
			noLimits+" readLine accumulates into a buffer sized from the remaining input and returns only on the CRLF "+
				"pair (Draft.java:70-87), with no per-line ceiling.",
			"line-limit",
			"the RFC-derived model rejects the over-length header line; the pinned Java client has no line limit and "+
				"lets the remaining checks decide. ws_core retains the CONFIGURED per-line budget as the safety "+
				"ceiling (JAVA_FAITHFUL_PLUS_SAFE); at hard ceilings the seed is an incomplete head, exactly as Java "+
				"records it.",
			section104),
		clientHandshakeDefinition("HS_BARE_LF", "bare-lf",
			"org.java-websocket.draft6455.client-handshake.bare-lf", readLineRef,
			"RFC 6455 section 4.1 requires the client to validate the server's opening handshake, and section 4.2.2 "+
				"requires that handshake to be a valid HTTP/1.1 response; RFC 9112 section 2.2 terminates lines with "+
				"CRLF and forbids a bare LF as a line terminator, so a bare-LF response is malformed and must be "+
				"refused.",
			"Draft.readLine returns a line ONLY on the CR-LF pair (Draft.java:78, `prev == '\\r' && cur == '\\n'`), so "+
				"a bare LF is an ordinary payload byte and its line folds into the following CRLF-terminated line as "+
				"one header. Java never refuses for the bare LF itself. The mapping records the client-side "+
				"consequence explicitly: unlike the server side, basicAccept still checks Upgrade and Connection "+
				"(Draft.java:188-191), so a folded response usually rejects NOT_MATCHED — for the WRONG reason, "+
				"through the wrong channel, and only when the fold happens to damage one of those two fields.",
			"bare-lf",
			"the RFC-derived model rejects the bare-LF response as malformed; the pinned Java client folds it and "+
				"judges the folded result. The divergence survives even where the folded outcome is also a rejection, "+
				"because the RFC reject and the Java reject have different causes and different channels, and a fold "+
				"that leaves Upgrade, Connection and Sec-WebSocket-Accept intact is accepted outright.",
			section41),
		clientHandshakeDefinition("HS_HEADER_NAME_NOT_TOKEN", "header-name-not-token",
			"org.java-websocket.draft6455.client-handshake.header-name-not-token", translateHTTP,
			"RFC 6455 section 4.1/4.2.2 requires the server's handshake to be a valid HTTP response; RFC 9112 "+
				"section 5 requires header field names to be HTTP tokens, so a non-token field name makes the message "+
				"invalid and the client must refuse it.",
			"Java performs no header-name token validation on either direction: translateHandshakeHttp splits each "+
				"line on the FIRST colon and stores whatever precedes it as the field name, unvalidated "+
				"(Draft.java:113-127); the only parse-level header rejection in the whole path is a line with no colon "+
				"at all (`not an http header`). A non-token name is therefore kept as a field the later checks never "+
				"look up, and the observable is decided by basicAccept and the accept comparison.",
			"invalid-token",
			"the RFC-derived model rejects the non-token header name; the pinned Java client stores it unvalidated. "+
				"The recorded client seed makes the mechanism visible: `Up grade` is stored as a field named `Up grade`, "+
				"so the lookup for `Upgrade` finds nothing and basicAccept rejects NOT_MATCHED — again the right "+
				"outcome for the wrong reason, and a non-token name on any header the client does not consult is "+
				"accepted outright.",
			section41),
		clientHandshakeDefinition("HS_DUPLICATE_HEADER", "duplicate-header",
			"org.java-websocket.draft6455.client-handshake.duplicate-header", translateHTTP,
			"RFC 6455 section 4.1/4.2.2 requires the client to validate the server's handshake as a valid HTTP "+
				"response; RFC 9110 section 5.3 forbids consuming a duplicated singleton field such as "+
				"Sec-WebSocket-Accept as one combined value, so a duplicated field must be refused.",
			"translateHandshakeHttp joins a repeated field into one value with the literal separator \"; \" "+
				"(Draft.java:119-125, `getFieldValue(pair[0]) + \"; \" + pair[1]`), on the client direction exactly as "+
				"on the server direction. The mapping records the client-side consequence: a duplicated "+
				"Sec-WebSocket-Accept joins to a string that cannot equal the single derived key, so it rejects "+
				"NOT_MATCHED, while a duplicated Upgrade joins to `websocket; websocket`, which fails basicAccept's "+
				"equalsIgnoreCase.",
			"duplicate-casing",
			"the RFC-derived model rejects the duplicated field; the pinned Java client joins and judges the joined "+
				"value. The rejection is a side effect of the join producing an unmatchable string, not a duplicate "+
				"check — so a field duplicated where the join is harmless (Connection, which is only tested with "+
				"`contains(\"upgrade\")`) is accepted outright.",
			section41),
	}
}

// messageFramingHeaderDefinitions ledger the two smuggling-shaped seeds
// individually (G3d). They are the same lenient-parse class as the existing
// server-handshake records, but the class they belong to is specifically HTTP
// message framing, which has its own safety consequence, so they are recorded
// on their own terms rather than folded into the class records.
func messageFramingHeaderDefinitions() []Definition {
	translateHTTP := "org.java_websocket.drafts.Draft:translateHandshakeHttp"
	section421 := []string{"rfc6455#section-4.2.1"}

	neverExamined := "Java-WebSocket 1.6.0 never examines HTTP message-framing headers on the handshake path. " +
		"translateHandshakeHttp (Draft.java:70-132) splits every line on the first colon and stores the pair into an " +
		"opaque HandshakeBuilder field map; nothing downstream reads it. This is verifiable by absence over the whole " +
		"pinned tree, and the absence was checked rather than assumed: the ONLY occurrence of the string " +
		"\"Content-Length\" anywhere in src/main/java is in the OUTBOUND error-response builder " +
		"(WebSocketImpl.java:458, which writes a Content-Length on the HTTP error page it sends), and the string " +
		"\"Transfer-Encoding\" does not occur anywhere in the tree at all. No request body is ever read: " +
		"acceptHandshakeAsServer checks only Sec-WebSocket-Version == 13 (Draft_6455.java:262-286) and " +
		"postProcessHandshakeResponseAsServer requires only a non-empty Sec-WebSocket-Key (Draft_6455.java:432-441), " +
		"and every byte after the terminating CRLFCRLF is handed to the frame decoder as remainder."

	safety := " SAFETY: ws_core is a WebSocket protocol core, never an HTTP intermediary — it does not forward the " +
		"request, does not read a body, and hands the post-head bytes to the frame layer as an explicit remainder " +
		"(rust/ws-core/src/handshake/server.rs), so no body-versus-frame confusion exists INSIDE the core, and the " +
		"handshake head itself stays inside the configured budgets under forbid(unsafe_code). The residual risk is " +
		"recorded rather than dismissed: a deployment that fronts this core with an HTTP intermediary which DOES " +
		"honour these framing fields could desynchronize the two parsers, which is the classic request-smuggling " +
		"shape. That is a deployment-topology concern above the core, and it is named here so the divergence is not " +
		"mistaken for a benign parse quirk."

	return []Definition{
		{
			Subject: "org.java-websocket.draft6455.server-handshake.content-length-ignored",
			RFCRefs: section421,
			RFCExpectation: "RFC 6455 section 4.2.1 requires the server to read the client's opening handshake as an " +
				"HTTP/1.1 request and to return an HTTP error response when the request is invalid. RFC 9112 section 6 " +
				"makes Content-Length a message-framing field a recipient MUST use to determine body length, and " +
				"requires a recipient that cannot determine the framing to reject the message. A handshake request " +
				"carrying Content-Length declares a body the WebSocket upgrade has no place for, so an RFC-conformant " +
				"server must act on that framing rather than ignore it.",
			RFCValue: "reject-or-consume: honour the declared message framing (refuse the upgrade, or consume the " +
				"declared body before the frame stream begins)",
			JavaRef: translateHTTP,
			JavaObservation: neverExamined + " RECORDED INPUT: the borrowed smuggling-shaped seed " +
				"rust/ws-core/fuzz-seeds/us011/content-length.hex, byte-verbatim " +
				"\"GET / HTTP/1.1\\r\\nContent-Length: 0\\r\\n\\r\\n\". Its recorded outcome in the committed replay is " +
				"NOT_MATCHED — and the cause is recorded precisely, because it matters: the rejection comes from the " +
				"ABSENT Sec-WebSocket-Version, not from the Content-Length line, which is parsed into the field map " +
				"and never consulted. The seeds `extension`, `subprotocol` and `valid-plus-suffix` in the same replay " +
				"show that an otherwise-complete request with unconsulted extra headers accepts.",
			JavaValue: "ignore: the message-framing field is parsed into the field map and never read; it can " +
				"neither cause nor prevent acceptance",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
			Rationale: "DIVERGENCE (server handshake, Content-Length ignored): the RFC requires the handshake to be " +
				"processed as a valid HTTP request whose declared message framing is honoured; shipped Java parses the " +
				"field into an opaque map and never reads it. This is the same lenient-parse class as the existing " +
				"never-examined server-handshake records, ledgered individually here because HTTP message framing " +
				"carries a distinct safety consequence that the class records do not name. WS_CORE SITE: " +
				"rust/ws-core/src/handshake/server.rs over rust/ws-core/src/handshake/http.rs (parse_java_head) " +
				"emulates the ignore exactly; pinned byte-for-byte by " +
				"rust/ws-core/tests/handshake_seeds.rs::us011_server_seeds_replay_with_java_model_expectations, whose " +
				"recorded reason for this seed is \"Java ignores Content-Length entirely; the missing version rejects " +
				"NOT_MATCHED\"." + safety + ownerDecision,
		},
		{
			Subject: "org.java-websocket.draft6455.server-handshake.transfer-encoding-ignored",
			RFCRefs: section421,
			RFCExpectation: "RFC 6455 section 4.2.1 requires the server to read the client's opening handshake as an " +
				"HTTP/1.1 request and to refuse an invalid one. RFC 9112 section 6.1 makes Transfer-Encoding a " +
				"message-framing field: a server that receives a Transfer-Encoding it cannot process MUST respond 501, " +
				"and a request whose framing is ambiguous MUST be rejected. Ignoring the field is not an option the " +
				"RFC offers.",
			RFCValue: "reject-or-consume: honour the declared transfer coding (refuse the upgrade, or decode the " +
				"declared body before the frame stream begins)",
			JavaRef: translateHTTP,
			JavaObservation: neverExamined + " RECORDED INPUT: the borrowed smuggling-shaped seed " +
				"rust/ws-core/fuzz-seeds/us011/transfer-encoding.hex, byte-verbatim " +
				"\"GET / HTTP/1.1\\r\\nTransfer-Encoding: identity\\r\\n\\r\\n\". Its recorded outcome is NOT_MATCHED, " +
				"caused by the ABSENT Sec-WebSocket-Version and not by the Transfer-Encoding line. The absence " +
				"evidence is stronger here than for Content-Length: the string \"Transfer-Encoding\" occurs NOWHERE in " +
				"the pinned src/main/java tree, in either direction, so there is no code path that could act on it.",
			JavaValue: "ignore: the transfer-coding field is parsed into the field map and never read; no chunked or " +
				"other transfer decoding exists anywhere on the handshake path",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
			Rationale: "DIVERGENCE (server handshake, Transfer-Encoding ignored): the RFC requires an unprocessable " +
				"transfer coding to be refused; shipped Java has no transfer-coding handling at all and the field is " +
				"inert. Ledgered individually alongside the Content-Length record for the same reason: the " +
				"lenient-parse class records do not name the message-framing safety consequence. WS_CORE SITE: " +
				"rust/ws-core/src/handshake/server.rs over rust/ws-core/src/handshake/http.rs (parse_java_head) " +
				"emulates the ignore exactly; pinned by " +
				"rust/ws-core/tests/handshake_seeds.rs::us011_server_seeds_replay_with_java_model_expectations, whose " +
				"recorded reason for this seed is \"Transfer-Encoding is ignored; the missing version rejects " +
				"NOT_MATCHED\"." + safety + ownerDecision,
		},
	}
}

// preOpenRefusalDefinitions ledger the pre-open poison strengthening (G3e).
//
// This record's class differs from every other record in the ledger, and the
// rationale says so plainly rather than letting the uniform record shape imply
// otherwise: the port is STRICTER than shipped Java here. It is a
// port-versus-Java safe strengthening on a corpus-invisible arm, not a
// Java-versus-RFC leniency the port emulates. The gap register offered either
// a record or a written justification for why no record was needed; a record
// that states its own class is the more honest of the two, and the owner
// amendment's disclosure mandate is what it serves.
func preOpenRefusalDefinitions() []Definition {
	return []Definition{
		{
			Subject: "org.java-websocket.websocketimpl.pre-open-send-refusal-recoverability",
			RFCRefs: []string{"rfc6455#section-4.1", "rfc6455#section-5.1"},
			RFCExpectation: "RFC 6455 section 4.1 establishes that the WebSocket connection exists only once the " +
				"opening handshake has completed successfully, and section 5.1 governs data transfer only from that " +
				"point. A send attempted before the handshake completes is outside the protocol entirely: the RFC " +
				"defines no wire behavior for it, and correspondingly says nothing that would require the connection " +
				"to remain usable afterwards. Both a recoverable refusal and a terminal one are consistent with the " +
				"text; the RFC does not choose.",
			RFCValue: "unspecified: the RFC neither requires nor forbids the connection remaining usable after a " +
				"pre-handshake send is refused",
			JavaRef: "org.java_websocket.WebSocketImpl:send",
			JavaObservation: "Shipped Java's refusal is RECOVERABLE. Every send funnels into the private " +
				"send(Collection) (WebSocketImpl.java:667-670), whose first statement is " +
				"`if (!isOpen()) { throw new WebsocketNotConnectedException(); }`. That throw mutates nothing: no " +
				"readyState assignment, no flush, no close bookkeeping, no queue change. The WebSocketImpl instance is " +
				"left exactly as it was, so the caller may catch the unchecked exception, let the handshake complete, " +
				"and send successfully afterwards. One ordering detail is part of the observation: sendFragmentedFrame " +
				"(WebSocketImpl.java:683-685) evaluates draft.continuousFrame(...) as the ARGUMENT of send(...), so an " +
				"invalid first text fragment throws IllegalArgumentException from Draft.isValid (Draft.java:210-239) " +
				"BEFORE the isOpen gate is reached. FIDELITY EVIDENCE: the Java sites above, read in the digest-pinned " +
				"quarantined 1.6.0 tree; the port-side arm and its divergence are disclosed in " +
				"protected/e4-autopong-eof-receipt.json honesty note 3.",
			JavaValue: "recoverable-refusal: WebsocketNotConnectedException is thrown, no state is mutated, and the " +
				"connection remains usable for a later send",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
			Rationale: "DIVERGENCE (pre-open sends, refusal recoverability) — AND THE DIRECTION IS THE UNUSUAL ONE: " +
				"the port is STRICTER than shipped Java, so this is a port-versus-Java safe strengthening, not a " +
				"Java-versus-RFC leniency the port reproduces. It is recorded because the owner amendment's mandate is " +
				"disclosure of divergence, and because the e4 lane disclosed it in a receipt where no ledger census " +
				"could reach it. PORT BEHAVIOR: ConnectionCore::handle_pre_open_command " +
				"(rust/ws-core/src/connection.rs) refuses every pre-handshake data and control send with " +
				"FailureCode::StateViolation — the same oracle projection Java's WebsocketNotConnectedException gets, " +
				"and the same one the post-handshake requireOpen gate uses — and then POISONS the core, " +
				"because the port applies one uniform partial-execution discipline to every fatal typed failure. " +
				"Java's connection stays usable; the port's does not. Pinned by " +
				"rust/ws-core/tests/close_eof.rs::data_and_control_sends_before_open_are_the_not_connected_rejection, " +
				"which asserts StateViolation, zero writes, zero corpus action counts, and then asserts that a " +
				"subsequent send on the same core also refuses. The continuousFrame ordering is pinned separately by " +
				"::send_fragment_before_open_validates_the_first_text_fragment_first (JavaNotSendable ahead of " +
				"StateViolation). SCOPE: the arm is corpus-invisible — no scenario in corpora/public/scenarios.jsonl " +
				"reaches NotYetConnected with a send, so this divergence cannot move the 74/74 live-oracle " +
				"confirmation, and it did not. SAFETY: refusing strictly is the conservative direction. The core " +
				"writes no byte, emits no event and counts no action; poisoning prevents a caller from treating a " +
				"connection whose command sequence has already diverged as if nothing happened, which is the same rule " +
				"every other fatal failure in the core follows. A caller wanting Java's recoverable semantics can " +
				"discard the refused core and construct another before the handshake, since the arm exists only before " +
				"the handshake completes. DISPOSITION NOTE: 'unresolved' is the frozen 1.0.0 vocabulary's only " +
				"retained-divergence term; the strengthening is deliberately retained, not left unexamined." +
				ownerDecision,
		},
	}
}
