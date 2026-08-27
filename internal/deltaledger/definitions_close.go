package deltaledger

// closeControlDefinitions are the batch-C close/control divergences
// (borrow-receipt-batch-c.json, also in-repo at
// drafts/borrow-receipt-batch-c.json), grounded in internal/corpora/derive.go
// and rust/ws-core/src/close.rs, and live-oracle-confirmed where
// corpus-visible (the 18 batch-C corpus flips are all inside the 74/74
// live-confirmed public run).
func closeControlDefinitions() []Definition {
	liveConfirmed := " Corpus expectations for this site are LIVE-ORACLE-CONFIRMED (74/74 public run against the real " +
		"pinned jar; 0 behavioral Rust-vs-live-Java divergences; us-live-oracle-confirmation-receipt.json)."

	return []Definition{
		{
			Subject: "org.java-websocket.draft6455.no-automatic-pong",
			RFCRefs: []string{"rfc6455#section-5.5.2", "rfc6455#section-5.5.3"},
			RFCExpectation: "RFC 6455 section 5.5.2 requires an endpoint that receives a Ping frame to send a Pong frame " +
				"with identical application data in response, unless it already sent a Close frame.",
			RFCValue: "auto-respond: an inbound ping produces a pong write with byte-identical payload",
			JavaRef:  "org.java_websocket.drafts.Draft_6455:processFrame",
			JavaObservation: "Under the pinned oracle protocol an inbound ping produces a ping semantic event and NO " +
				"automatic pong write (quirk Q18): the reference model's observable space contains no auto-pong " +
				"(derive.go:671-674 emits only the ping event). Batch-C receipt: 'STRIPPED (US-015): automatic-pong machinery " +
				"(AutomaticPongPolicy/plan_batch) — the reference model's observable space contains NO automatic pong " +
				"(derive.go:671-675, Q18); the core never replies on its own'.",
			JavaValue:    "no-auto-respond: ping delivers one ping event; no pong write is ever produced by the core",
			AutobahnRefs: []string{"autobahn-v25.10.1:2.1"},
			Rationale: "DIVERGENCE (automatic pong): the RFC requires a pong response to every ping; the pinned runtime's " +
				"oracle-observable core never auto-pongs — ping is delivered as an event and any pong policy lives ABOVE the " +
				"core (rust/ws-core/src/control.rs module doc). FIDELITY EVIDENCE: derive.go:671-674; corpus family " +
				"ping-inbound (us005.pub.0002, us005.pub.0071) live-executed with no pong write." + liveConfirmed +
				" Pinned by rust/ws-core/tests/ping_pong.rs::empty_ping_and_pong_deliver_events_and_never_reply and " +
				"::repeated_pings_deliver_and_write_nothing; seed rust/ws-core/fuzz-seeds/us015/no-unwanted-reply.hex. " +
				"WS_CORE SITE: rust/ws-core/src/connection.rs process_inbound ping arm; rust/ws-core/src/control.rs " +
				"(behavior-map documentation). SAFETY: not writing is strictly safer than writing (no reply amplification " +
				"surface); an embedding layer that owes RFC pong semantics can implement them above the core from the " +
				"delivered ping event without any core change." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.websocketimpl.send-control-no-payload-cap",
			RFCRefs: []string{"rfc6455#section-5.5"},
			RFCExpectation: "RFC 6455 section 5.5 limits every control-frame payload to 125 bytes or less; a conforming " +
				"sender must refuse to emit a ping/pong whose payload exceeds 125 bytes.",
			RFCValue: "refuse-send: an over-125-byte local ping/pong command is rejected before any write",
			JavaRef:  "org.java_websocket.WebSocketImpl:sendFrame",
			JavaObservation: "The pinned runtime's send path performs NO control payload-size check (quirk Q17: the oracle " +
				"Execution.sendControl mirrors WebSocketImpl.sendFrame, which never checks): an oversized local ping/pong is " +
				"encoded with an extended length and sent successfully. Batch-C receipt: 'STRIPPED (US-015): send-path control " +
				"payload cap — Execution.sendControl performs NO size check (Q17); oversized control payloads send " +
				"successfully with extended length ...; pinned by tests (200-byte ping sends)'.",
			JavaValue:    "send: the over-125-byte control payload is encoded with extended length and written to the wire",
			AutobahnRefs: []string{"autobahn-v25.10.1:2.5"},
			Rationale: "DIVERGENCE (send-path control cap): the RFC caps control payloads at 125 bytes; the pinned runtime " +
				"sends oversized control payloads without any check. NOTE the deliberate asymmetry: INBOUND over-125 control " +
				"frames are still rejected 1002 at the marker/length site (see the control-extended-length-marker record), " +
				"pinned by rust/ws-core/src/connection.rs (Quirk Q17 asymmetry comment, line ~1051). FIDELITY EVIDENCE: " +
				"batch-C receipt strip record; quirk Q17 quarantined-source read (Execution.sendControl / " +
				"WebSocketImpl.sendFrame); pinned by rust/ws-core/tests/ping_pong.rs::oversized_control_payloads_send_" +
				"successfully_quirk_q17 and rust/ws-core/tests/core_semantics.rs::send_payload_limit_asymmetry_matches_java_" +
				"control_frames. WS_CORE SITE: rust/ws-core/src/connection.rs send_ping/send_pong arms; " +
				"rust/ws-core/src/control.rs. SAFETY: the outbound payload is still bounded by the configured send/write " +
				"budgets and queue backpressure (typed refusal, never unbounded growth); emitting a legal-length-encoded " +
				"frame with a large control payload is interoperability-lenient, not memory-unsafe." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.closeframe.one-byte-close-payload",
			RFCRefs: []string{"rfc6455#section-5.5.1"},
			RFCExpectation: "RFC 6455 section 5.5.1 defines the close payload as either empty or beginning with a 2-byte " +
				"unsigned status code; a close frame with a 1-byte payload is malformed and the receiver must fail the " +
				"connection (protocol error 1002 as a FAILURE).",
			RFCValue: "reject: treat the 1-byte close payload as a protocol failure (fail the connection)",
			JavaRef:  "org.java_websocket.framing.CloseFrame:setPayload",
			JavaObservation: "CloseFrame.setPayload maps a one-byte close payload to code 1002 with an empty reason and the " +
				"frame is processed as a VALID close (quirk Q11): the connection performs an ordinary close handshake " +
				"reporting 1002, rather than failing on a malformed frame. Batch-C receipt: 'STRIPPED (US-016): " +
				"PayloadLengthOne rejection — CloseFrame.setPayload maps one byte to code 1002 with empty reason, a VALID " +
				"close (Q11; corpus family close-payload-1)'.",
			JavaValue:    "accept-as-close: the 1-byte payload becomes a valid close carrying code 1002, empty reason",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.3.2"},
			Rationale: "DIVERGENCE (one-byte close payload): the RFC treats a 1-byte close payload as malformed; the pinned " +
				"runtime converts it into a VALID close with code 1002 and completes the close handshake. FIDELITY EVIDENCE: " +
				"corpus family close-payload-1 (us005.pub.0035)." + liveConfirmed + " Pinned by " +
				"rust/ws-core/tests/close_eof.rs::one_byte_close_payload_is_a_valid_1002_close. WS_CORE SITE: " +
				"rust/ws-core/src/framing.rs close-payload parse (Q11) feeding rust/ws-core/src/close.rs vocabulary. SAFETY: " +
				"the outcome is a deterministic well-typed close; no allocation or state hazard is introduced by treating the " +
				"malformed byte as a coded close." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.closeframe.constructor-payload-echo",
			RFCRefs: []string{"rfc6455#section-5.5.1"},
			RFCExpectation: "RFC 6455 section 5.5.1 requires an endpoint receiving a Close frame (having not sent one) to " +
				"send a Close frame in response, typically echoing the received status code; the response close is expected " +
				"to reflect the received code.",
			RFCValue: "echo-received-code: the responding close frame carries the code received from the peer",
			JavaRef:  "org.java_websocket.framing.CloseFrame:constructor",
			JavaObservation: "The pinned runtime's echoed close frame OBJECT always carries the CloseFrame constructor " +
				"payload [0x03,0xe8] (code 1000) regardless of the received code, and the inbound close-frame RECORD " +
				"observable carries the constructor payload too (quirks Q10/Q19; derive.go closeMap sites). Batch-C receipt: " +
				"'STRIPPED (US-016): AcknowledgementMismatch exact code/reason echo — the echoed frame object always carries " +
				"the constructor payload [0x03,0xe8] (Q10), and the inbound close frame RECORD does too'; 'CORRECTED " +
				"(US-016): close-while-open echoes then transitions to CLOSING (not closed)'.",
			JavaValue:    "echo-constructor-payload: the echo and the frame record carry [0x03,0xe8] (1000) regardless of the received code",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.1.2"},
			Rationale: "DIVERGENCE (close echo payload): the RFC-shaped echo reflects the received status code; the pinned " +
				"runtime echoes the constructor payload [0x03,0xe8] while open (Q19 echo-while-open with Q10 constructor " +
				"payload) and records the inbound close with the same constructor payload. The GOVERNING close detail " +
				"(code/reason reported at termination) still comes from the received frame via the close translate path — " +
				"only the echoed/recorded frame object diverges. FIDELITY EVIDENCE: corpus families close-remote " +
				"(us005.pub.0026, us005.pub.0050, us005.pub.0061) and close-remote-empty (us005.pub.0046)." + liveConfirmed +
				" Pinned by rust/ws-core/tests/close_eof.rs::inbound_close_while_open_echoes_the_constructor_payload and " +
				"::inbound_close_while_closing_terminates_without_echo. WS_CORE SITE: rust/ws-core/src/connection.rs close " +
				"echo arm; rust/ws-core/src/event.rs (Q10 frame-record doc); rust/ws-core/src/framing.rs close constructor " +
				"payload (Q10). SAFETY: the echo is a fixed 4-byte frame; no attacker-controlled bytes are reflected, which " +
				"is strictly more conservative than echoing peer data." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.websocketimpl.eof-ordinary-close",
			RFCRefs: []string{"rfc6455#section-7.1.4", "rfc6455#section-7.1.5"},
			RFCExpectation: "RFC 6455 sections 7.1.4/7.1.5 distinguish abnormal closure classes: EOF without a prior close " +
				"frame is an abnormal closure (status 1006 semantics) distinct from EOF after an incomplete close handshake, " +
				"EOF with unflushed writes, or EOF before the peer's acknowledgement; an RFC-strict endpoint reports these as " +
				"distinct failure classes.",
			RFCValue: "distinct-failure-classes: EOF maps to per-situation abnormal-closure failures (1006 family)",
			JavaRef:  "org.java_websocket.WebSocketImpl:eot",
			JavaObservation: "The pinned runtime treats EVERY transport EOF as the ordinary close vocabulary (quirk Q20): " +
				"WebSocketImpl.eot completes the handshake from closing, and EOF while open reports the pinned 1006 " +
				"transport close; a governing local/remote close carries its own code/reason over the transport origin, with " +
				"remote = was-closing and handshake_complete propagated (derive.go closeMap eof sites). Batch-C receipt: " +
				"'STRIPPED (US-016): ... the EOF failure classes (UnexpectedEofOpen, EofBeforePeerClose, " +
				"EofBeforeAcknowledgement, EofBeforeCloseWriteFlushed) — Java ... treats every EOF as the ordinary Q20 close " +
				"vocabulary'.",
			JavaValue:    "ordinary-close-vocabulary: every EOF resolves through the single Q20 close mapping (no distinct failure classes)",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.1.1"},
			Rationale: "DIVERGENCE (EOF classification): the RFC-strict design distinguishes EOF failure classes; the " +
				"pinned runtime collapses every EOF into the ordinary close vocabulary with the governing close's detail. " +
				"FIDELITY EVIDENCE: corpus families eof-abnormal (us005.pub.0062), close-local-then-eof (us005.pub.0022), " +
				"state-eof-in-closed (us005.pub.0070)." + liveConfirmed + " Pinned by " +
				"rust/ws-core/tests/close_eof.rs::local_close_then_eof_reports_the_governing_close_over_transport and " +
				"::remote_close_then_eof_keeps_handshake_complete plus rust/ws-core/tests/core_semantics.rs EOF tests. " +
				"WS_CORE SITE: rust/ws-core/src/connection.rs eof arm (Q20); rust/ws-core/src/close.rs CloseOrigin::Transport. " +
				"SAFETY: every EOF path still terminates the connection deterministically with a typed close detail and no " +
				"duplicate terminal events (pinned by a_third_close_after_terminal_is_a_state_violation); no resource is " +
				"leaked by the coarser vocabulary. Residual honest gap: EOF BEFORE the handshake completes remains an " +
				"Unimplemented refusal (dossier G11), not covered by this record." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.closeframe.isvalid-rejection-chain",
			RFCRefs: []string{"rfc6455#section-7.4.1", "rfc6455#section-7.4.2"},
			RFCExpectation: "RFC 6455 sections 7.4.1/7.4.2 define the close-code table: 1000-2999 are reserved for the " +
				"protocol/extensions (specific defined values legal on the wire), 3000-3999 are library/framework codes and " +
				"4000-4999 private-use codes; an endpoint validates received/sent codes against this table and treats " +
				"reserved values (1005, 1006, 1015) as never-on-the-wire.",
			RFCValue: "rfc-close-code-table: validate codes per the section 7.4 registry classes",
			JavaRef:  "org.java_websocket.framing.CloseFrame:isValid",
			JavaObservation: "The pinned runtime validates close codes through CloseFrame.isValid's literal rejection chain " +
				"(quirk Q13; framing/CloseFrame.java:226-243; derive.go closeIsValidRejection:618-635), in Java's exact check " +
				"order: 1007-with-empty-reason rejects AS 1007; 1005-with-reason rejects 1002; 1016..2999 rejects 1002; 1006, " +
				"1015, 1005, 1004, <1000 and >4999 reject 1002; everything else (including all of 3000-4999 and 1000-1003, " +
				"1007-1014 pairs that pass the chain) is wire-legal.",
			JavaValue: "isvalid-chain: Java's ordered rejection chain with its reported codes (1007 special-case; otherwise 1002)",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.9.1"},
			Rationale: "DIVERGENCE (close-code table semantics): the RFC's registry classes and Java's isValid chain " +
				"disagree in both membership granularity and the REPORTED code (Java reports the 1007-empty-reason rejection " +
				"as 1007, everything else as 1002, and bans the entire 1016-2999 band). FIDELITY EVIDENCE: derive.go " +
				"closeIsValidRejection:618-635; corpus families close-code-invalid-wire (us005.pub.0019, us005.pub.0033, " +
				"us005.pub.0041) and send-close-invalid-code (us005.pub.0000, code 999 -> JAVA_INVALID_DATA close 1002)." +
				liveConfirmed + " Pinned by rust/ws-core/src/close.rs::close_code_rejection (US-009 pure fn, called by the " +
				"US-016 close paths per the US-009 owner decision) and tests rust/ws-core/tests/close_eof.rs::" +
				"send_close_invalid_code_rejects_without_a_frame, ::inbound_close_code_1005_rejects_at_translate, " +
				"::send_close_1007_with_empty_reason_reports_1007. WS_CORE SITE: rust/ws-core/src/close.rs (close_code_rejection); " +
				"rust/ws-core/src/connection.rs close paths. SAFETY: the chain is a pure total function over (u16, str); " +
				"every rejection is a typed deterministic outcome; no code path transmits a Java-illegal code." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.closeframe.setcode-1015-normalization",
			RFCRefs: []string{"rfc6455#section-7.4.1"},
			RFCExpectation: "RFC 6455 section 7.4.1 designates 1015 (TLS handshake failure) as a reserved value that MUST " +
				"NOT be sent in a Close frame by an endpoint; an API request to send 1015 should be refused AS the 1015 " +
				"violation it is.",
			RFCValue: "refuse-1015: reject the local send_close(1015) request as the reserved-code violation itself",
			JavaRef:  "org.java_websocket.framing.CloseFrame:setCode",
			JavaObservation: "CloseFrame.setCode silently normalizes a REQUESTED send close code of 1015 (TLS_ERROR) to " +
				"1005 (NOCODE) BEFORE any validation runs (quirk Q14; framing/CloseFrame.java:179-184; derive.go " +
				"sendClose:888-897); the subsequent isValid chain then evaluates 1005 — so send_close(1015) with an empty " +
				"reason is rejected AS the 1005 case (reported 1002), never as 1015.",
			JavaValue:    "normalize-then-validate: 1015 silently becomes 1005 pre-validation; the rejection reports Java's 1005-case code",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.9.1"},
			Rationale: "DIVERGENCE (1015 send normalization): the RFC-shaped refusal names the 1015 reserved-code " +
				"violation; the pinned runtime silently rewrites 1015 to 1005 before validation and the observable rejection " +
				"is the 1005-case outcome. FIDELITY EVIDENCE: derive.go sendClose:888-897 (setCode normalization mirrored); " +
				"quarantined-source citation framing/CloseFrame.java:179-184 (batch receipts and close.rs module doc). " +
				"Pinned by rust/ws-core/src/close.rs::normalize_send_close_code (US-009 pure fn) and tests " +
				"rust/ws-core/tests/close_eof.rs::send_close_1015_normalizes_to_1005_then_rejects_1002 and " +
				"rust/ws-core/tests/core_semantics.rs::send_close_1015_silently_normalizes_to_1005. WS_CORE SITE: " +
				"rust/ws-core/src/close.rs; rust/ws-core/src/connection.rs send_close arm. SAFETY: the normalization is a " +
				"pure code rewrite on the LOCAL send path only; no reserved code reaches the wire (the isValid chain still " +
				"rejects 1005/1015), so the RFC's on-the-wire prohibition is never violated." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.closeframe.invalid-utf8-reason-runtime-rejection",
			RFCRefs: []string{"rfc6455#section-5.5.1", "rfc6455#section-8.1"},
			RFCExpectation: "RFC 6455 sections 5.5.1/8.1 require the close-frame reason (after the 2-byte code) to be " +
				"valid UTF-8; an endpoint receiving a close frame with an invalid-UTF-8 reason fails the connection with " +
				"1007 (invalid frame payload data).",
			RFCValue: "reject: 1007 close on an invalid-UTF-8 close reason",
			JavaRef:  "org.java_websocket.framing.CloseFrame:isValid",
			JavaObservation: "In the pinned runtime an invalid-UTF-8 close reason decodes to a NULL reason whose isValid " +
				"dereference raises a NullPointerException-class runtime rejection with NO close code (quirk Q12; oracle " +
				"failure code JAVA_RUNTIME_REJECTION at translate time, close_code None), instead of the RFC's typed 1007 " +
				"close.",
			JavaValue:    "runtime-rejection: JAVA_RUNTIME_REJECTION with no close code, at translate time",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.5.1"},
			Rationale: "DIVERGENCE (invalid-UTF-8 close reason vocabulary): the RFC fails with 1007; the pinned runtime " +
				"surfaces a NullPointerException-class rejection with NO close code (Q12). Added beyond the three task source " +
				"lists under the completeness cross-check: every behavioral quirk with an RFC counterpart is ledgered. " +
				"FIDELITY EVIDENCE: quirk Q12 (rust/ws-core/src/framing.rs:536-552 strict reason decode; " +
				"rust/ws-core/src/error.rs JavaRuntimeRejection doc; derive.go javaRuntimeRejection vocabulary). Pinned by " +
				"rust/ws-core/tests/close_eof.rs::invalid_utf8_close_reason_is_the_java_runtime_rejection (frame consumed, no " +
				"close code, no frame record). WS_CORE SITE: rust/ws-core/src/framing.rs close-reason decode (Q12); " +
				"rust/ws-core/src/error.rs. SAFETY: the rejection is a typed terminal failure over a bounded (<=125-byte) " +
				"control payload; the invalid reason is never delivered to the application." + ownerDecision,
		},
	}
}
