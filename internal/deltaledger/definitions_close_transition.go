package deltaledger

// closeTransitionDefinitions is the single record the owner's
// rejected-close-transition-divergence decision requires
// (protected/us012-us016-owner-decisions-2026-08-28-formal.json, sha256
// d7a54e2c5aac48cc9ef1b3afa19d14593555e1fce7cb49fed69484ba24bfc352). That
// decision ordered the port changed to match shipped Java AND ordered a ledger
// record "whatever the outcome". The change was implemented and measured; the
// decision's own escape clause fired, so the record documents a divergence
// that is deliberately NOT resolved in code, with the measurement that
// justifies it.
//
// Appended AFTER the 34 existing definitions so the committed hash chain's
// prefix is unchanged.
func closeTransitionDefinitions() []Definition {
	return []Definition{
		{
			Subject: "org.java-websocket.websocketimpl.rejected-local-close-readystate",
			RFCRefs: []string{"rfc6455#section-7.1.3", "rfc6455#section-7.4.1"},
			RFCExpectation: "RFC 6455 section 7.1.3 defines the CLOSING state as the state an endpoint occupies once it " +
				"has SENT a Close frame; section 7.4.1 reserves 1004, 1005, 1006 and 1015 and the 1016-2999 range so they " +
				"MUST NOT be set as a status code in a Close control frame sent to a peer. An endpoint whose local close " +
				"request names such a code therefore sends no Close frame at all, and having sent none it has not entered " +
				"CLOSING: the connection is still OPEN and the local close request simply failed.",
			RFCValue: "stay-open: a local close request refused before any Close frame reaches the wire leaves the " +
				"connection in OPEN",
			JavaRef: "org.java_websocket.WebSocketImpl:close",
			JavaObservation: "The pinned 1.6.0 tree has TWO local-close entry points that disagree with each other on this " +
				"exact point, and the disagreement is the finding. (A) The shipped library API " +
				"WebSocketImpl.close(int, String, boolean) (WebSocketImpl.java:463-507) builds the close frame inside a try " +
				"block — new CloseFrame(); setReason; setCode; isValid(); sendFrame (WebSocketImpl.java:482-486) — and CATCHES " +
				"the InvalidDataException that CloseFrame.isValid raises for a reserved code " +
				"(framing/CloseFrame.java:226-243, the 'closecode must not be sent over the wire' throw at " +
				"framing/CloseFrame.java:241). The catch logs, notifies onWebsocketError and calls " +
				"flushAndClose(CloseFrame.ABNORMAL_CLOSE, \"generated frame is invalid\", false) " +
				"(WebSocketImpl.java:488-492); flushAndClose (WebSocketImpl.java:584-606) records the close code and calls " +
				"onWebsocketClosing but never reaches closeConnection, so control returns and the method's UNCONDITIONAL " +
				"tail assignment readyState = ReadyState.CLOSING (WebSocketImpl.java:503) runs. Via this entry point a " +
				"rejected local close DOES enter CLOSING, and no frame is written. (B) The pinned oracle adapter's " +
				"send_close action (java-oracle/src/main/java/OracleEngine.java:461-475) is a DIFFERENT path: it constructs " +
				"the CloseFrame itself, calls frame.isValid() at OracleEngine.java:470, and declares 'throws " +
				"InvalidDataException', so the same exception PROPAGATES out of the method. WebSocketImpl.close is never " +
				"invoked, its line 503 is never reached, and the adapter's emitOutbound, close-detail assignment, " +
				"close_initiated event and transition(State.CLOSING) at OracleEngine.java:471-474 are all skipped. THE LIVE " +
				"RECORDING RESOLVES WHICH PATH THE CORPUS MEASURES: the real pinned Java-WebSocket 1.6.0 runtime (jar sha256 " +
				"eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f, adapter self-verified at startup) ran " +
				"public case us005.pub.0000 — send_close code 999 reason \"bad\" from an open connection — and recorded " +
				"outcome error, error.code JAVA_INVALID_DATA, error.close_code 1002, detail 'closecode must not be sent over " +
				"the wire: 999', frames 0, and final_state OPEN " +
				"(protected/us005-corpora/live/public/transcript.jsonl; 74/74 reconciled, " +
				"us-live-oracle-confirmation-receipt.json).",
			JavaValue: "entry-point-dependent: WebSocketImpl.close ends in CLOSING on the caught InvalidDataException " +
				"path (WebSocketImpl.java:503) while OracleEngine.sendClose lets the same exception propagate and the " +
				"live-recorded state stays open",
			AutobahnRefs: []string{"autobahn-v25.10.1:7.1.1", "autobahn-v25.10.1:7.3.1"},
			AutobahnResult: "EXECUTED BUT NOT PROBATIVE FOR THIS SITE, stated so rather than implied. The whole 7.* close " +
				"family was re-executed against ws-testee on the pinned image " +
				"crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074 " +
				"(pull=never) at this branch: 37/37 cases executed, 34 OK / 3 INFORMATIONAL / 0 FAILED, per-case behavior " +
				"classes IDENTICAL to the E5b baseline evidence/rust/autobahn-e5b/index-run1.json with zero changed cases. " +
				"That run confirms no regression, but wstest drives the testee's close behavior from the WIRE and never " +
				"asks the application to initiate a close with a reserved status code, so it does NOT exercise the " +
				"rejected-local-close arm and is cited here only as the non-regression anchor.",
			AutobahnValue: "close-family-behavior-classes-unchanged: 34 OK / 3 INFORMATIONAL / 0 FAILED across 7.*, " +
				"per-case identical to the E5b baseline; the site itself is unexercised by the suite",
			Rationale: "DIVERGENCE (rejected local close, ReadyState): the RFC leaves an endpoint that never sent a Close " +
				"frame in OPEN; shipped WebSocketImpl.close reaches CLOSING anyway via its unconditional tail assignment. " +
				"OWNER DECISION: protected/us012-us016-owner-decisions-2026-08-28-formal.json (sha256 " +
				"d7a54e2c5aac48cc9ef1b3afa19d14593555e1fce7cb49fed69484ba24bfc352, verified at read), decision id " +
				"rejected-close-transition-divergence, ruled MATCH JAVA'S BEHAVIOR — change the port so a rejected local " +
				"close enters CLOSING — with an explicit escape clause: STOP and surface the conflict if re-verification " +
				"shows the change would break a LIVE-CONFIRMED observable. RESOLUTION: NOT RESOLVED IN CODE, because the " +
				"escape clause fired on measurement rather than on argument. The change WAS implemented at " +
				"rust/ws-core/src/connection.rs send_close (transition to Closing plus the abnormal-close detail, the exact " +
				"shape assurance/formal/close-model.tla's seeded defect defect.close.rejected-send-transitions declares), " +
				"the release harness was rebuilt, and the public corpus was re-run end to end. Result read from the real " +
				"corporactl process: executed 74, passed 73, FAILED 1, exit 1, the single failure being 'us005.pub.0000: " +
				"final_state closing, expected open'; the Rust transcript digest moved from " +
				"fd3f7a1c1eb0eeed0a7b214eac2dc517ab169511ce266d98280f7eff571f2326 to " +
				"207eaf0b79624f5894c00af9e0231e46e0c45b7b2aaa35bd1d24d7eb90b5abce, and final_state was the ONLY behavioral " +
				"field to change on ANY of the 74 cases. Since live Java's own recording of that case is final_state open, " +
				"the source reading loses to the live observable exactly as the decision instructed, and the change was " +
				"reverted: ws_core is byte-identical in behavior, the transcript digest is back to fd3f7a1c and evaluate is " +
				"74/74 exit 0. FIDELITY EVIDENCE: the Java sites above, all read in the digest-pinned quarantined 1.6.0 " +
				"tree; the live transcript; the measured corpus failure. WS_CORE SITE (deliberately unchanged): " +
				"rust/ws-core/src/connection.rs send_close rejection arm, pinned by " +
				"rust/ws-core/tests/close_eof.rs::send_close_invalid_code_rejects_without_a_frame, whose ReadyState::Open " +
				"assertion now carries the full conflict record so no later lane 'fixes' it from the shipped source alone. " +
				"internal/corpora/derive.go sendClose (derive.go:890-912) agrees with the port and with the live oracle. " +
				"SAFETY: staying OPEN after a refused close is the conservative option — it neither fabricates a close " +
				"handshake the peer never saw nor writes any byte to the wire (frames 0 in both the live and the port " +
				"recording); an embedding layer that wants the shipped library's CLOSING semantics can drive them above the " +
				"core from the returned typed failure. FORMAL MODEL: assurance/formal/close-model.tla's " +
				"RejectedSendDoesNotTransition remains TRUE and, contrary to the note recorded there, must NOT be inverted; " +
				"see the E3 handoff note in " +
				"workspace/orchestrator/verified-java-websocket-port-claude/drafts/close-transition-receipt.json." +
				" DISPOSITION NOTE: 'unresolved' is the frozen 1.0.0 vocabulary's only retained-divergence term; the " +
				"divergence is deliberately retained on owner-sanctioned live evidence, not left unexamined.",
		},
	}
}
