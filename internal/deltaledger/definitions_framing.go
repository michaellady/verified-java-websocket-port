package deltaledger

// framingDefinitions are the batch-A framing divergences (borrow-receipt-batch-a.json
// stripped_or_corrected + honesty_notes), grounded in the reference model
// internal/corpora/derive.go and, where corpus-visible, live-oracle-confirmed
// by the 74/74 public run (us-live-oracle-confirmation-receipt.json).
func framingDefinitions() []Definition {
	translateSingleFrame := "org.java_websocket.drafts.Draft_6455:translateSingleFrame"
	liveConfirmed := " Corpus expectations for this site are LIVE-ORACLE-CONFIRMED (74/74 public run against the real " +
		"pinned jar; 0 behavioral Rust-vs-live-Java divergences; us-live-oracle-confirmation-receipt.json)."

	return []Definition{
		{
			Subject: "org.java-websocket.draft6455.framing.noncanonical-extended-length",
			RFCRefs: []string{"rfc6455#section-5.2"},
			RFCExpectation: "RFC 6455 section 5.2 requires the minimal number of bytes to encode the payload length; a " +
				"16-bit extended length under 126 or a 64-bit extended length under 65536 is non-minimal and the receiver " +
				"must fail the connection (protocol error 1002).",
			RFCValue: "reject: fail the WebSocket connection with 1002 on a non-minimal extended payload length",
			JavaRef:  translateSingleFrame,
			JavaObservation: "translateSingleFrame parses 16- and 64-bit extended lengths without any minimality check " +
				"(reference model derive.go:399-420 mirrors the pinned decode); non-minimal encodings are accepted and the " +
				"frame is processed normally. Batch-A receipt: 'STRIPPED: NonCanonicalLength16/NonCanonicalLength64 rejection " +
				"(Java accepts non-minimal extended lengths; derive.go:400-420)'.",
			JavaValue:    "accept: the non-minimally-encoded frame decodes and is processed normally",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
			Rationale: "DIVERGENCE (noncanonical extended length, 16-bit and 64-bit forms): the RFC requires rejecting " +
				"non-minimal length encodings with 1002; the pinned Java runtime performs no minimality check and accepts both " +
				"forms. FIDELITY EVIDENCE: derive.go:399-420 (US-005-calibrated reference model); batch-A receipt strip record; " +
				"seeds rust/ws-core/fuzz-seeds/us012/noncanonical-16.hex and rust/ws-core/fuzz-seeds/us012/noncanonical-64.hex " +
				"replayed by rust/ws-core/tests/frame_codec.rs::noncanonical_extended_lengths_are_accepted_like_shipped_java. " +
				"WS_CORE SITE: rust/ws-core/src/framing.rs extended-length decode. SAFETY: the decoded length still passes the " +
				"control-payload gate and the configured frame-size gate (1009) before any allocation, so a non-minimal " +
				"encoding cannot bypass the allocation ceilings; forbid(unsafe_code)." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.draft6455.framing.mask-by-role-acceptance",
			RFCRefs: []string{"rfc6455#section-5.1", "rfc6455#section-5.2"},
			RFCExpectation: "RFC 6455 section 5.1 requires client-to-server frames to be masked and server-to-client frames " +
				"to be unmasked; a server must fail the connection (1002) on an unmasked client frame and a client must fail " +
				"it on a masked server frame.",
			RFCValue: "reject: fail the WebSocket connection with 1002 on a role-inappropriate mask bit",
			JavaRef:  translateSingleFrame,
			JavaObservation: "The pinned runtime accepts either masking toward either role: translateSingleFrame unmasks " +
				"when the mask bit is set and otherwise reads the payload directly, with no role check (reference model " +
				"derive.go:439-447 documents the accepted-either-way discipline and scopes the corpus to spec-conformant " +
				"masking). Batch-A receipt: 'STRIPPED: IncorrectMasking mask-by-role rejection (pinned runtime accepts either " +
				"masking toward either role)'; batch-C extends the same stance to the control path.",
			JavaValue:    "accept: the frame decodes regardless of the mask-bit/role combination",
			AutobahnRefs: []string{"autobahn-v25.10.1:1.1.1"},
			Rationale: "DIVERGENCE (mask-by-role): the RFC requires rejecting role-inappropriate masking with 1002; the " +
				"pinned Java runtime accepts either masking toward either role. FIDELITY EVIDENCE: derive.go:439-447 (source " +
				"citation in the batch-A receipt; the shape is corpus-invisible because the corpus scopes itself to " +
				"spec-conformant masking, so this record rests on the quarantined-source read plus the US-005 calibration of " +
				"derive.go). Pinned by rust/ws-core/tests/frame_codec.rs::mask_direction_mismatches_are_accepted_toward_either_role " +
				"and rust/ws-core/tests/ping_pong.rs::mask_role_mismatch_seeds_are_accepted_not_rejected; seeds " +
				"rust/ws-core/fuzz-seeds/us012/wrong-mask-client.hex, rust/ws-core/fuzz-seeds/us012/wrong-mask-server.hex, " +
				"rust/ws-core/fuzz-seeds/us015/wrong-mask-client.hex, rust/ws-core/fuzz-seeds/us015/wrong-mask-server.hex. " +
				"WS_CORE SITE: rust/ws-core/src/framing.rs mask handling (unmask-if-masked, no role gate). SAFETY: unmasking is " +
				"a pure XOR over an already-bounded payload; accepting either mask state adds no allocation or panic surface; " +
				"outbound masking still follows the RFC role rule (client sends masked, server sends unmasked), so the port " +
				"never EMITS role-inappropriate frames." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.draft6455.framing.length-64bit-high-bit",
			RFCRefs: []string{"rfc6455#section-5.2"},
			RFCExpectation: "RFC 6455 section 5.2 requires the most significant bit of the 64-bit extended payload length " +
				"to be 0; a frame declaring a length with the high bit set is malformed and the receiver must fail the " +
				"connection (protocol error 1002).",
			RFCValue: "reject: fail the WebSocket connection with 1002 on a 64-bit length with the high bit set",
			JavaRef:  "org.java_websocket.drafts.Draft_6455:translateSingleFramePayloadLength",
			JavaObservation: "The pinned runtime reads the 8 length bytes into a signed Java long, so a high-bit length " +
				"parses as a NEGATIVE long with untested downstream behavior; the reference model marks such lengths outside " +
				"the generated space (derive.go:265-268 rejects 64-bit lengths beyond the generated space as unsupported). " +
				"Batch-A receipt strip record and honesty note: 'a 64-bit length with the high bit set parses as a huge " +
				"unsigned length and rejects 1009 at the length site; shipped Java reads it as a negative long with untested " +
				"downstream behavior ... corpus-invisible'.",
			JavaValue: "undefined-in-evidence: negative signed-long length with untested downstream behavior (outside the " +
				"verified space); the port deliberately parses unsigned and rejects 1009 at length site 10",
			AutobahnRefs: []string{"autobahn-v25.10.1:9.1.1"},
			Rationale: "DIVERGENCE (64-bit high-bit length): the RFC requires a 1002 failure; pinned Java's behavior is " +
				"UNOBSERVED (negative-long parse, untested downstream; outside the reference model's generated space per " +
				"derive.go:265-268), and ws_core deliberately does NOT emulate the untested negative-length path: it parses the " +
				"length unsigned and the huge value fails the ordinary configured frame-size gate with 1009 at length site 10. " +
				"This is the one deliberately divergence-shaped port choice recorded in the batch-A honesty notes, now ledgered " +
				"under the owner mandate. FIDELITY EVIDENCE: batch-A receipt honesty note; seed " +
				"rust/ws-core/fuzz-seeds/us012/high-bit-64.hex replayed by " +
				"rust/ws-core/tests/frame_codec.rs::high_bit_64_length_is_an_ordinary_oversized_length_at_site_10. WS_CORE " +
				"SITE: rust/ws-core/src/framing.rs 64-bit length decode. SAFETY: the unsigned parse plus the checked " +
				"frame-size gate (1009) means no allocation is ever attempted for the declared length; this is a safety " +
				"ceiling the owner decision explicitly retains (bounded allocation remains binding)." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.draft6455.framing.post-payload-rejection-site",
			RFCRefs: []string{"rfc6455#section-5.2", "rfc6455#section-5.5"},
			RFCExpectation: "RFC 6455 section 5.2 requires failing the connection when RSV bits are nonzero without a " +
				"negotiated extension, and section 5.5 forbids fragmented control frames (FIN=0); an RFC-strict endpoint " +
				"detects both at the frame header, before consuming the payload.",
			RFCValue: "reject: fail with 1002 at header-detection time, before the payload is consumed",
			JavaRef:  translateSingleFrame,
			JavaObservation: "The pinned runtime consumes the FULL frame (header plus payload) before throwing on RSV bits " +
				"or a non-final control frame; the observable failure site is post-payload with close 1002. Batch-A receipt: " +
				"'CORRECTED: RSV-bit and control-fin rejections moved from header time to Java's post-payload site (full frame " +
				"consumed, close 1002)'.",
			JavaValue:    "reject: fail with 1002 only after the full frame (header plus payload) is consumed",
			AutobahnRefs: []string{"autobahn-v25.10.1:3.1", "autobahn-v25.10.1:5.1"},
			Rationale: "DIVERGENCE (rejection SITE, not verdict): both the RFC expectation and pinned Java reject RSV-bit " +
				"and non-final control frames with 1002, but Java's observable rejection site is after the full frame is " +
				"consumed, not at the header. FIDELITY EVIDENCE: corpus families rsv-bit (us005.pub.0005, us005.pub.0029, " +
				"us005.pub.0058) and control-nonfin (us005.pub.0020)." + liveConfirmed + " Pinned by " +
				"rust/ws-core/tests/frame_codec.rs::reserved_bits_reject_1002_only_after_the_full_frame and " +
				"::non_fin_control_frame_rejects_1002_after_the_full_frame (control path: " +
				"rust/ws-core/tests/ping_pong.rs::non_fin_control_rejects_1002_after_the_full_frame); seeds " +
				"rust/ws-core/fuzz-seeds/us012/rsv1.hex, rsv2.hex, rsv3.hex, fragmented-control.hex. WS_CORE SITE: " +
				"rust/ws-core/src/framing.rs post-payload checks. SAFETY: the payload consumed before rejection is still " +
				"bounded by the control-payload and configured frame-size gates, so the deferred site cannot force unbounded " +
				"buffering; forbid(unsafe_code)." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.draft6455.framing.control-extended-length-marker-site",
			RFCRefs: []string{"rfc6455#section-5.5"},
			RFCExpectation: "RFC 6455 section 5.5 requires control frames to have a payload length of 125 bytes or less; " +
				"a control frame declaring an extended length (marker 126 or 127) violates this and must fail the connection " +
				"(1002).",
			RFCValue: "reject: fail with 1002 on an over-125 control payload length (the RFC states no detection site)",
			JavaRef:  "org.java_websocket.drafts.Draft_6455:translateSingleFramePayloadLength",
			JavaObservation: "translateSingleFramePayloadLength rejects an extended-length CONTROL frame at header byte 2 " +
				"(the marker byte), before reading any extended length bytes (reference model derive.go:402-407: control with " +
				"marker >= 126 fails at consumed-site 2 with close 1002). Batch-A receipt: 'control extended-length " +
				"header-byte-2 site'.",
			JavaValue:    "reject: fail with 1002 at header byte 2 (marker byte), before the extended length bytes are read",
			AutobahnRefs: []string{"autobahn-v25.10.1:2.5"},
			Rationale: "DIVERGENCE (detection-site granularity): verdicts agree (1002), but pinned Java rejects the control " +
				"extended-length MARKER at header byte 2 without reading the declared length, so its consumed-byte observable " +
				"differs from an RFC-minimal parser that reads the length first. FIDELITY EVIDENCE: derive.go:402-407; corpus " +
				"family control-oversize (us005.pub.0057, us005.pub.0059)." + liveConfirmed + " Pinned by " +
				"rust/ws-core/tests/frame_codec.rs::extended_length_control_marker_rejects_1002_before_reading_the_length and " +
				"rust/ws-core/tests/ping_pong.rs::extended_length_control_marker_rejects_at_the_base_header; seed " +
				"rust/ws-core/fuzz-seeds/us012/oversized-control.hex. WS_CORE SITE: rust/ws-core/src/framing.rs control " +
				"length-marker gate. SAFETY: rejecting at the marker byte consumes LESS input than the RFC-shaped alternative; " +
				"no allocation occurs for the declared length." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.draft6455.framing.consumed-bytes-error-sites",
			RFCRefs: []string{"rfc6455#section-5.2"},
			RFCExpectation: "RFC 6455 section 5.2 defines the frame grammar; an RFC-minimal parser fails at the earliest " +
				"byte that proves the violation (e.g. the opcode byte for an unknown opcode) and processes each frame " +
				"independently of its transport chunk.",
			RFCValue: "reject: fail at the earliest violating byte; frames already decoded from the same chunk remain processed",
			JavaRef:  "org.java_websocket.drafts.Draft_6455:translateFrame",
			JavaObservation: "The pinned runtime's per-site consumption semantics (quirk Q25, mirrored at every error site " +
				"by derive.go inputStep/translate): unknown opcode at byte 2, control extended-length marker at byte 2, " +
				"control-length/frame-size gates at bytes 2/4/10 (the length site), RSV/control-fin post-payload at the full " +
				"frame; and a translate rejection discards ALL frames decoded from the same transport chunk and suppresses the " +
				"input_chunk observable. Batch-A receipt: 'CORRECTED: per-site consumed_bytes reconciled with derive.go quirk Q25'.",
			JavaValue: "reject: Java's per-site consumed-byte offsets (2/4/10/full-frame) with same-chunk decoded frames " +
				"discarded and input_chunk suppressed",
			AutobahnRefs: []string{"autobahn-v25.10.1:4.1.1"},
			Rationale: "DIVERGENCE (error-site observables): the reject verdicts match the RFC, but the pinned runtime's " +
				"consumed-byte offsets and its discard-the-chunk translate semantics are Java-specific observables an " +
				"RFC-minimal parser would not produce. FIDELITY EVIDENCE: derive.go quirk-Q25 sites (batch-A receipt " +
				"correction record); corpus families bad-opcode (us005.pub.0036, us005.pub.0065) and multi-frame-chunk " +
				"(us005.pub.0043, us005.pub.0053)." + liveConfirmed + " Pinned by rust/ws-core/tests/frame_codec.rs (Q25 site " +
				"tests, e.g. ::prior_valid_frame_is_discarded_when_a_later_frame_fails_translate). WS_CORE SITE: " +
				"rust/ws-core/src/framing.rs per-site consumed accounting; rust/ws-core/src/event.rs consumed_bytes " +
				"observable. SAFETY: error-site accounting is observational only; every path still terminates with a typed " +
				"failure and bounded state." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.charsetfunctions.two-stage-utf8-timing",
			RFCRefs: []string{"rfc6455#section-8.1"},
			RFCExpectation: "RFC 6455 section 8.1 requires an endpoint receiving a text message with invalid UTF-8 to fail " +
				"the connection with 1007; a strictly-validating endpoint rejects a text frame whose payload ends in a " +
				"dangling incomplete UTF-8 sequence when the message completes, without first recording the frame as valid.",
			RFCValue: "reject: 1007 on invalid UTF-8, detected by one strict validation pass (no frame recorded first)",
			JavaRef:  "org.java_websocket.util.Charsetfunctions:isValidUTF8",
			JavaObservation: "The pinned runtime validates text in TWO stages (quirk Q15): the translate-time Hoehrmann DFA " +
				"(Charsetfunctions.isValidUTF8) ACCEPTS a payload ending in a dangling incomplete multi-byte prefix, so the " +
				"frame is recorded; the strict process-time gate (Charsetfunctions.stringUtf8) then rejects the assembled " +
				"message with 1007. Cross-fragment text is strictly validated only at the fin on the assembled payload. " +
				"Batch-A receipt: 'two-stage Q15 timing preserved (translate DFA accepts dangling tails, frame recorded, " +
				"strict 1007 at process)'.",
			JavaValue:    "reject: 1007 at process time AFTER the frame record; dangling tails pass the translate-time DFA",
			AutobahnRefs: []string{"autobahn-v25.10.1:6.1.1"},
			Rationale: "DIVERGENCE (validation timing): both reject invalid UTF-8 with 1007, but pinned Java's two-stage " +
				"gate first records the frame (translate DFA accepts dangling incomplete tails) and only the process-time " +
				"strict gate rejects, producing a frame-record observable an RFC-strict single-pass validator would not emit. " +
				"FIDELITY EVIDENCE: corpus family invalid-utf8-text (us005.pub.0056, us005.pub.0067)." + liveConfirmed +
				" Pinned by rust/ws-core/tests/messages.rs::truncated_tails_record_the_frame_then_reject_1007_at_process_time " +
				"and ::the_two_gates_diverge_exactly_on_dangling_incomplete_tails (independent cross-check " +
				"::both_gates_agree_with_the_standard_library_on_complete_inputs); seeds rust/ws-core/fuzz-seeds/us013/" +
				"truncated-two.hex, truncated-three.hex, truncated-four.hex. WS_CORE SITE: rust/ws-core/src/message.rs (both " +
				"gates, module doc cites the formal targets). SAFETY: both gates are total functions over bounded buffers; " +
				"the deferred rejection cannot deliver invalid text to the application (the strict gate always runs before " +
				"delivery)." + ownerDecision,
		},
		{
			Subject: "org.java-websocket.draft6455.buffer-limit-check-sites",
			RFCRefs: []string{"rfc6455#section-10.4"},
			RFCExpectation: "RFC 6455 section 10.4 expects implementations to enforce their message/buffer limits; a " +
				"strictly-checking endpoint verifies the accumulated size before buffering every fragment, failing with 1009 " +
				"(message too big) at the first violating fragment.",
			RFCValue: "reject: 1009 at the first fragment that exceeds the configured cap, at every fragment boundary",
			JavaRef:  "org.java_websocket.drafts.Draft_6455:checkBufferLimit",
			JavaObservation: "The pinned runtime checks the cumulative fragment total only at message STARTS and FINS " +
				"(checkBufferLimit, quirk Q23; reference model derive.go processDataFrame comment): an over-cap fin rejects " +
				"1009 with the accounting retained, while a NON-FIN continuation that overflows instead trips the adapter's " +
				"own accounting as BUFFER_LIMIT_EXCEEDED with NO close code (quirk Q23 overflow split). Batch-A receipt " +
				"failure-vocabulary correction: 'BUFFER_LIMIT_EXCEEDED without close code for the adapter add-bounded " +
				"continuation overflow'.",
			JavaValue: "reject-split: 1009 at starts/fins only; a non-fin continuation overflow is BUFFER_LIMIT_EXCEEDED " +
				"with no close code",
			AutobahnRefs: []string{"autobahn-v25.10.1:9.1.1"},
			Rationale: "DIVERGENCE (limit check sites and overflow vocabulary): the RFC-shaped expectation checks every " +
				"fragment; pinned Java checks only at starts and fins and splits the overflow observable (1009 vs " +
				"BUFFER_LIMIT_EXCEEDED-no-close-code) by fragment position. FIDELITY EVIDENCE: derive.go processDataFrame " +
				"(checkBufferLimit-at-starts-and-fins comment); corpus family buffer-limit-frame (us005.pub.0031)." +
				liveConfirmed + " Pinned by rust/ws-core/tests/fragmentation.rs::plus_one_retention_rejects_1009_at_the_fin_" +
				"with_accounting_retained, ::non_fin_continuation_overflow_is_the_adapter_add_bounded_failure and " +
				"::exact_retention_at_the_cap_delivers; seeds rust/ws-core/fuzz-seeds/us014/exact-retention.hex, " +
				"plus-one-retention.hex. WS_CORE SITE: rust/ws-core/src/framing.rs (Q23 sites) and rust/ws-core/src/fragment.rs. " +
				"SAFETY: the configured caps still bound every buffer before growth (add-bounded accounting); the divergence " +
				"is WHERE the check fires and WHICH typed failure reports it, never whether a cap exists." + ownerDecision,
		},
	}
}
