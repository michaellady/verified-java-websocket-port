package main

// CuratedMutations is the committed, deterministic operator table: every
// mutant is one exact-literal substitution at a named ws_core behavioral
// site. Order is the campaign order. Operators cover the audit's demanded
// classes: comparison flips (< <-> <=), off-by-one at the pinned length
// sites (2/4/10/125/126/127), close-code table entry swaps, UTF-8 DFA
// transition swaps, mask XOR drop, counter increment drops, and
// fragment-state transition swaps.
func CuratedMutations() []Mutation {
	const framing = "rust/ws-core/src/framing.rs"
	const message = "rust/ws-core/src/message.rs"
	const closeFile = "rust/ws-core/src/close.rs"
	const connection = "rust/ws-core/src/connection.rs"
	const fragment = "rust/ws-core/src/fragment.rs"
	return []Mutation{
		// --- US-012: masking -------------------------------------------------
		{
			ID: "m012-mask-xor-drop", Operator: "mask-xor-drop", File: framing,
			Match:   "*byte ^= key[index % 4];",
			Replace: "*byte ^= key[index % 4] & 0x00;",
			Note:    "unmask/mask becomes the identity (payloads stay masked)",
		},
		{
			ID: "m012-mask-modulus-swap", Operator: "mask-key-cycle-swap", File: framing,
			Match:   "*byte ^= key[index % 4];",
			Replace: "*byte ^= key[index % 2];",
			Note:    "four-byte repeating key degrades to two bytes",
		},
		// --- US-012: header/length decode sites ------------------------------
		{
			ID: "m012-control-ext-marker-flip", Operator: "comparison-flip", File: framing,
			Match:   "if opcode.is_control() && marker >= 126 {",
			Replace: "if opcode.is_control() && marker > 126 {",
			Note:    "control frame with the 126 escape stops rejecting early",
		},
		{
			ID: "m012-control-limit-off-by-one", Operator: "off-by-one-125", File: framing,
			Match:   "if opcode.is_control() && payload_len > CONTROL_PAYLOAD_LIMIT {",
			Replace: "if opcode.is_control() && payload_len >= CONTROL_PAYLOAD_LIMIT {",
			Note:    "control payload of exactly 125 starts rejecting",
		},
		{
			ID: "m012-frame-cap-off-by-one", Operator: "off-by-one-cap", File: framing,
			Match:   "if payload_len > max_frame_payload_bytes {",
			Replace: "if payload_len >= max_frame_payload_bytes {",
			Note:    "frame exactly at the configured cap starts rejecting 1009",
		},
		{
			ID: "m012-header-need-2-off-by-one", Operator: "off-by-one-site-2", File: framing,
			Match:   "if buf.len() < 2 {",
			Replace: "if buf.len() < 3 {",
			Note:    "two-byte headers never decode (site-2 buffering broken)",
		},
		{
			ID: "m012-extended16-need-off-by-one", Operator: "off-by-one-site-4", File: framing,
			Match:   "if buf.len() < 4 {",
			Replace: "if buf.len() < 3 {",
			Note:    "16-bit length reads one byte early at site 4",
		},
		{
			ID: "m012-extended64-need-off-by-one", Operator: "off-by-one-site-10", File: framing,
			Match:   "if buf.len() < 10 {",
			Replace: "if buf.len() < 9 {",
			Note:    "64-bit length reads short at site 10",
		},
		{
			ID: "m012-span-header16-arith", Operator: "span-arithmetic", File: framing,
			Match:   "header = 4;",
			Replace: "header = 3;",
			Note:    "span scan miscounts the 16-bit escape header",
		},
		{
			ID: "m012-length16-endian-swap", Operator: "length-byte-swap", File: framing,
			Match:   "u64::from(u16::from_be_bytes([buf[2], buf[3]])),",
			Replace: "u64::from(u16::from_be_bytes([buf[3], buf[2]])),",
			Note:    "16-bit extended length decodes little-endian",
		},
		// --- US-012: post-payload validity -----------------------------------
		{
			ID: "m012-rsv-check-weaken", Operator: "condition-weaken", File: framing,
			Match:   "if header.rsv1 || header.rsv2 || header.rsv3 {",
			Replace: "if header.rsv1 && header.rsv2 && header.rsv3 {",
			Note:    "single reserved bits stop rejecting 1002",
		},
		{
			ID: "m012-control-fin-flip", Operator: "polarity-flip", File: framing,
			Match:   "if header.opcode.is_control() && !header.fin {",
			Replace: "if header.opcode.is_control() && header.fin {",
			Note:    "fin controls reject, fragmented controls pass",
		},
		{
			ID: "m016-close-constructor-payload", Operator: "constant-swap", File: framing,
			Match:   "pub const CLOSE_CONSTRUCTOR_PAYLOAD: [u8; 2] = [0x03, 0xe8];",
			Replace: "pub const CLOSE_CONSTRUCTOR_PAYLOAD: [u8; 2] = [0x03, 0xe9];",
			Note:    "Q10 constructor payload drifts by one",
		},
		{
			ID: "m013-translate-dfa-drop", Operator: "gate-drop", File: framing,
			Match:   "if header.opcode == Opcode::Text && !Charsetfunctions::is_valid_utf8(&payload) {",
			Replace: "if false && header.opcode == Opcode::Text && !Charsetfunctions::is_valid_utf8(&payload) {",
			Note:    "translate-time 1007 UTF-8 gate silently disabled",
		},
		// --- US-012: outbound length encoding --------------------------------
		{
			ID: "m012-encode-125-boundary", Operator: "off-by-one-125", File: framing,
			Match:   "if length <= 125 {",
			Replace: "if length < 125 {",
			Note:    "length 125 encodes with the noncanonical 16-bit escape",
		},
		{
			ID: "m012-encode-16-boundary", Operator: "off-by-one-127", File: framing,
			Match:   "} else if length <= 0xffff {",
			Replace: "} else if length < 0xffff {",
			Note:    "length 65535 encodes with the 64-bit escape",
		},
		// --- US-014: fragment-state transitions ------------------------------
		{
			ID: "m014-start-during-open-swap", Operator: "fragment-transition-swap", File: framing,
			Match: "if self.continuous.active_opcode().is_some() {", Occurrence: 1,
			Replace: "if self.continuous.active_opcode().is_none() {",
			Note:    "fragment start during an open sequence stops rejecting",
		},
		{
			ID: "m014-data-during-frag-swap", Operator: "fragment-transition-swap", File: framing,
			Match: "if self.continuous.active_opcode().is_some() {", Occurrence: 2,
			Replace: "if self.continuous.active_opcode().is_none() {",
			Note:    "unfragmented data during a sequence stops rejecting",
		},
		{
			ID: "m014-orphan-continuation-swap", Operator: "fragment-transition-swap", File: framing,
			Match:   "if self.continuous.active_opcode().is_none() {",
			Replace: "if self.continuous.active_opcode().is_some() {",
			Note:    "orphan continuations accepted; real continuations reject",
		},
		{
			ID: "m014-continuation-cap-off-by-one", Operator: "off-by-one-cap", File: framing,
			Match:   "if next > max_buffered_bytes as u64 {",
			Replace: "if next >= max_buffered_bytes as u64 {",
			Note:    "exact-boundary continuation append starts rejecting",
		},
		{
			ID: "m014-assembled-cap-off-by-one", Operator: "off-by-one-cap", File: framing,
			Match:   "if size > max_message_bytes {",
			Replace: "if size >= max_message_bytes {",
			Note:    "exact-limit assembled message starts rejecting 1009",
		},
		{
			ID: "m014-buffered-reset-drop", Operator: "counter-reset-drop", File: framing,
			Match:   "*message_buffered = 0;",
			Replace: "*message_buffered = 1;",
			Note:    "fragment accounting never returns to zero after delivery",
		},
		{
			ID: "m014-orphan-close-code-swap", Operator: "close-code-swap", File: framing,
			Match:   "// derive.go: EnforceContinuationStart -> 1002.\n            return Err(TypedProtocolFailure::java_invalid_data(1002));",
			Replace: "// derive.go: EnforceContinuationStart -> 1002.\n            return Err(TypedProtocolFailure::java_invalid_data(1007));",
			Note:    "orphan continuation reports 1007 instead of 1002",
		},
		// --- US-013: UTF-8 DFA transition swaps ------------------------------
		{
			ID: "m013-utf8-e0-window", Operator: "dfa-window-swap", File: message,
			Match:   "next_min: 0xa0,",
			Replace: "next_min: 0x80,",
			Note:    "E0 overlong window admits 80..9F (overlongs accepted)",
		},
		{
			ID: "m013-utf8-ed-window", Operator: "dfa-window-swap", File: message,
			Match:   "next_max: 0x9f,",
			Replace: "next_max: 0xbf,",
			Note:    "ED window admits A0..BF (surrogates accepted)",
		},
		{
			ID: "m013-utf8-f0-window", Operator: "dfa-window-swap", File: message,
			Match:   "next_min: 0x90,",
			Replace: "next_min: 0x80,",
			Note:    "F0 window admits 80..8F (overlong four-byte accepted)",
		},
		{
			ID: "m013-utf8-f4-window", Operator: "dfa-window-swap", File: message,
			Match:   "next_max: 0x8f,",
			Replace: "next_max: 0xbf,",
			Note:    "F4 window admits 90..BF (beyond U+10FFFF accepted)",
		},
		{
			ID: "m013-utf8-orphan-lead-accept", Operator: "dfa-error-drop", File: message,
			Match: "self.errored = true;\n                return;", Occurrence: 1,
			Replace: "return;",
			Note:    "orphan continuations / overlong leads silently accepted",
		},
		{
			ID: "m013-utf8-f5-accept", Operator: "dfa-error-drop", File: message,
			Match: "self.errored = true;\n                return;", Occurrence: 2,
			Replace: "return;",
			Note:    "F5..FF leads silently accepted",
		},
		{
			ID: "m013-utf8-2byte-length-swap", Operator: "dfa-transition-swap", File: message,
			Match:   "0xc2..=0xdf => Pending {\n                remaining: 1,",
			Replace: "0xc2..=0xdf => Pending {\n                remaining: 2,",
			Note:    "two-byte sequences demand a third continuation byte",
		},
		// --- US-016: close-code tables ---------------------------------------
		{
			ID: "m016-normalize-target-swap", Operator: "close-table-swap", File: closeFile,
			Match:   "if code == 1015 { 1005 } else { code }",
			Replace: "if code == 1015 { 1006 } else { code }",
			Note:    "Q14 normalization lands on 1006 instead of 1005",
		},
		{
			ID: "m016-normalize-trigger-swap", Operator: "close-table-swap", File: closeFile,
			Match:   "if code == 1015 { 1005 } else { code }",
			Replace: "if code == 1014 { 1005 } else { code }",
			Note:    "Q14 normalization triggers on 1014 instead of 1015",
		},
		{
			ID: "m016-1007-entry-swap", Operator: "close-table-swap", File: closeFile,
			Match:   "if code == 1007 && reason.is_empty() {\n        return Some(1007);\n    }",
			Replace: "if code == 1007 && reason.is_empty() {\n        return Some(1002);\n    }",
			Note:    "empty-reason 1007 rejection reports 1002",
		},
		{
			ID: "m016-1005-reason-flip", Operator: "polarity-flip", File: closeFile,
			Match:   "if code == 1005 && !reason.is_empty() {",
			Replace: "if code == 1005 && reason.is_empty() {",
			Note:    "1005 rejection fires on the empty reason instead",
		},
		{
			ID: "m016-range-lower-off-by-one", Operator: "off-by-one-close-range", File: closeFile,
			Match:   "if code > 1015 && code < 3000 {",
			Replace: "if code >= 1015 && code < 3000 {",
			Note:    "1015 joins the 1016..2999 rejection band",
		},
		{
			ID: "m016-range-upper-off-by-one", Operator: "off-by-one-close-range", File: closeFile,
			Match:   "if code > 1015 && code < 3000 {",
			Replace: "if code > 1015 && code <= 3000 {",
			Note:    "3000 joins the reserved rejection band",
		},
		{
			ID: "m016-1006-entry-swap", Operator: "close-table-swap", File: closeFile,
			Match:   "if code == 1006",
			Replace: "if code == 1008",
			Note:    "1006 becomes wire-legal; 1008 rejects",
		},
		{
			ID: "m016-range-4999-off-by-one", Operator: "off-by-one-close-range", File: closeFile,
			Match:   "|| !(1000..=4999).contains(&code)",
			Replace: "|| !(1000..=5000).contains(&code)",
			Note:    "5000 becomes wire-legal",
		},
		// --- US-016: close payload parse defaults ----------------------------
		{
			ID: "m016-parse-empty-default-swap", Operator: "close-table-swap", File: framing,
			Match:   "0 => (1000u16, String::new()),",
			Replace: "0 => (1002u16, String::new()),",
			Note:    "empty close payload parses as 1002 instead of 1000",
		},
		{
			ID: "m016-parse-onebyte-default-swap", Operator: "close-table-swap", File: framing,
			Match:   "1 => (1002u16, String::new()),",
			Replace: "1 => (1000u16, String::new()),",
			Note:    "one-byte close payload parses as 1000 instead of 1002",
		},
		// --- US-015/US-016: connection state gates and counters --------------
		{
			ID: "m012-inbound-frame-counter-drop", Operator: "counter-increment-drop", File: connection,
			Match: "self.frame_count += 1;", Occurrence: 1,
			Replace: "self.frame_count += 0;",
			Note:    "inbound frames stop counting toward counts.frames",
		},
		{
			ID: "m015-outbound-frame-counter-drop", Operator: "counter-increment-drop", File: connection,
			Match: "self.frame_count += 1;", Occurrence: 2,
			Replace: "self.frame_count += 0;",
			Note:    "outbound frames stop counting toward counts.frames",
		},
		{
			ID: "m016-eof-action-counter-drop", Operator: "counter-increment-drop", File: connection,
			Match: "self.action_count = self.action_count.saturating_add(1);", Occurrence: 1,
			Replace: "self.action_count = self.action_count.saturating_add(0);",
			Note:    "EOF stops counting as an action",
		},
		{
			ID: "m015-command-action-counter-drop", Operator: "counter-increment-drop", File: connection,
			Match: "self.action_count = self.action_count.saturating_add(1);", Occurrence: 2,
			Replace: "self.action_count = self.action_count.saturating_add(0);",
			Note:    "commands stop counting as actions",
		},
		{
			ID: "m012-consumed-chunk-drop", Operator: "counter-increment-drop", File: connection,
			Match:   "self.consumed_bytes = self.consumed_bytes.saturating_add(chunk_len);",
			Replace: "self.consumed_bytes = self.consumed_bytes.saturating_add(0);",
			Note:    "surviving chunks stop counting as consumed",
		},
		{
			ID: "m016-closed-gate-flip", Operator: "state-gate-flip", File: connection,
			Match:   "if self.state == ReadyState::Closed && !chunk.is_empty() {",
			Replace: "if self.state == ReadyState::Closed && chunk.is_empty() {",
			Note:    "closed state accepts data bytes, rejects empty chunks",
		},
		{
			ID: "m016-closing-gate-swap", Operator: "state-gate-flip", File: connection,
			Match:   "if self.state == ReadyState::Closing && frame.opcode != Opcode::Closing {",
			Replace: "if self.state == ReadyState::Closing && frame.opcode == Opcode::Closing {",
			Note:    "closing state accepts data frames, rejects the close ack",
		},
		{
			ID: "m016-echo-branch-flip", Operator: "close-transition-swap", File: connection,
			Match:   "if was_closing {\n            self.transition(ReadyState::Closed, TransitionCause::ReceiveClose);\n            return Ok(());\n        }",
			Replace: "if !was_closing {\n            self.transition(ReadyState::Closed, TransitionCause::ReceiveClose);\n            return Ok(());\n        }",
			Note:    "close-while-open terminates without echo; ack echoes",
		},
		{
			ID: "m016-echo-payload-swap", Operator: "close-echo-swap", File: connection,
			Match:   "CLOSE_CONSTRUCTOR_PAYLOAD.to_vec(),",
			Replace: "frame.payload.clone(),",
			Note:    "echo carries the wire payload (the stripped RFC echo), not Q10",
		},
		{
			ID: "m016-eof-code-swap", Operator: "close-code-swap", File: connection,
			Match:   "_ => (1006, EOF_DEFAULT_REASON.to_owned()),",
			Replace: "_ => (1000, EOF_DEFAULT_REASON.to_owned()),",
			Note:    "abnormal EOF reports 1000 instead of 1006",
		},
		{
			ID: "m016-eof-remote-flip", Operator: "polarity-flip", File: connection,
			Match:   "let remote = if self.handshake_completed {\n            self.state == ReadyState::Closing",
			Replace: "let remote = if self.handshake_completed {\n            self.state != ReadyState::Closing",
			Note:    "the EOF remote flag inverts",
		},
		{
			ID: "m016-send-close-normalize-skip", Operator: "gate-drop", File: connection,
			Match:   "let code = normalize_send_close_code(code);",
			Replace: "let code = code;",
			Note:    "Q14 normalization skipped on the send path",
		},
		{
			ID: "m015-open-gate-flip", Operator: "state-gate-flip", File: connection,
			Match:   "if self.state != ReadyState::Open {",
			Replace: "if self.state == ReadyState::Open {",
			Note:    "sends require NOT-open (everything inverts)",
		},
		{
			ID: "m013-send-payload-gate-off-by-one", Operator: "off-by-one-cap", File: connection,
			Match:   "&& len > self.config.max_buffered_bytes()",
			Replace: "&& len >= self.config.max_buffered_bytes()",
			Note:    "exact-boundary send payload starts rejecting",
		},
		{
			ID: "m015-send-fragment-dfa-drop", Operator: "gate-drop", File: connection,
			Match:   "if !self.draft.send_sequence_open()",
			Replace: "if false && !self.draft.send_sequence_open()",
			Note:    "first-fragment text DFA gate disabled",
		},
		// Equivalence probes: designed to stress the survivor workflow.
		// The mask-counter stall is killable only by pinning the documented
		// counter-based key derivation (a port-side seam property); the
		// post-fatal step counter is analysed as truly equivalent
		// (EquivalentAnalyses).
		{
			ID: "mprobe-mask-counter-stall", Operator: "counter-increment-drop", File: connection,
			Match:   "self.mask_counter = self.mask_counter.wrapping_add(1);",
			Replace: "self.mask_counter = self.mask_counter.wrapping_add(0);",
			Note:    "equivalence probe: deterministic mask keys repeat (Q28: never observable)",
		},
		{
			ID: "mprobe-step-counter-fatal-drop", Operator: "counter-increment-drop", File: connection,
			// The Ok-arm site ends with a comma; this semicolon literal is
			// unique to the fatal-poison arm.
			Match: "self.step = self.step.saturating_add(1);", Occurrence: 1,
			Replace: "self.step = self.step.saturating_add(0);",
			Note:    "equivalence probe: step counter stalls on the poisoning input only",
		},
		// --- Backpressure atomicity ------------------------------------------
		// Review 01a045b0 blocking finding (unrelayed until 01a045e0): the
		// backpressure oracle asserted only that nothing was EMITTED, so a
		// refusal that had already committed state would have survived. This
		// mutant commits the input accounting BEFORE the atomicity precheck,
		// which is invisible to the emit-only check and fatal to the
		// strengthened full-observable comparison.
		{
			ID: "m012-backpressure-nonatomic-input-commit", Operator: "atomicity-violation", File: connection,
			Match: "        // Atomicity precheck: nothing has mutated yet, so a refused input\n" +
				"        // can be retried identically after draining.\n" +
				"        if self.events.available() < self.byte_input_event_bound(spans.len()) {",
			Replace: "        self.input_bytes = new_input_total;\n" +
				"        // Atomicity precheck: nothing has mutated yet, so a refused input\n" +
				"        // can be retried identically after draining.\n" +
				"        if self.events.available() < self.byte_input_event_bound(spans.len()) {",
			Note: "input accounting is committed before the backpressure precheck, so a refused input mutates counts",
		},
		// --- Oracle-polarity probes ------------------------------------------
		// These three exist to prove the FUZZ ORACLES themselves fire, not
		// just the curated unit suites: each corrupts the core in a way that
		// only one specific adversarial oracle can see. They are ordinary
		// mutants (scratch-only, never committed) so the polarity proof is
		// re-runnable by anyone with `mutctl run -only mpol-...`.
		{
			ID: "mpol-panic-span-mask-header", Operator: "polarity-probe-panic", File: framing,
			Match:   "if data[at + 1] & 0x80 != 0 {\n                header += 4;\n            }",
			Replace: "if data[at + 1] & 0x80 != 0 {\n                header += 3;\n            }",
			Note: "masked spans come out one byte short so translate slices past the span end: " +
				"proves the no-panic oracle (drive_checked/catch_unwind) actually fires",
		},
		{
			ID: "mpol-nondeterminism-global-mask", Operator: "polarity-probe-determinism", File: connection,
			Match: "self.mask_counter = self.mask_counter.wrapping_add(1);",
			Replace: "{\n            static E1_POLARITY_GLOBAL: std::sync::atomic::AtomicU64 =\n" +
				"                std::sync::atomic::AtomicU64::new(0);\n" +
				"            self.mask_counter = E1_POLARITY_GLOBAL\n" +
				"                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)\n" +
				"                .wrapping_add(1);\n        }",
			Note: "mask-key derivation becomes process-global, so replaying the same seed diverges: " +
				"proves the determinism and rechunk-invariance oracles actually fire",
		},
		{
			ID: "mpol-unbounded-input-accounting", Operator: "polarity-probe-bounded-alloc", File: connection,
			Match:   "Some(total) if total <= max_input => total,",
			Replace: "Some(total) if total <= max_input || true => total,",
			Note: "the max_input_bytes gate is removed so input accounting grows unbounded: " +
				"proves the bounded-allocation oracle actually fires",
		},
		// --- AC5-named defect classes ----------------------------------------
		// The AC5 clauses of US-013..US-016 name specific defect classes by
		// hand; each one below is the literal seeded defect for a named class
		// so the AC5 evidence is class-complete, not merely operator-complete.
		//
		// THIS COMMENT CANNOT FAIL, AND US-020's OWN AC5 CLAUSE WAS NEVER GIVEN
		// THE SAME TREATMENT. Both halves of that are closed in
		// internal/defectclass: the seven classes US-020 AC5 names are PARSED out
		// of the PRD, every one binds to a seeded variant that must resolve in
		// the shipped tree, and `ac5ctl run` executes each variant's named
		// detector and MEASURES which normalized observation fields it moves.
		// TestAC5RegisterCampaignBindingHolds (main_test.go) is what keeps that
		// register and this table from drifting apart: a register row that
		// claims to be part of this campaign must actually be a row of it,
		// literal for literal.
		{
			// US-013 AC5 "event-order".
			ID: "m013-close-event-order-swap", Operator: "event-order-swap", File: connection,
			Match: "self.close_detail = Some(detail.clone());\n        self.emit(SemanticEventKind::Close(detail));\n" +
				"        if was_closing {\n            self.transition(ReadyState::Closed, TransitionCause::ReceiveClose);\n" +
				"            return Ok(());\n        }",
			Replace: "self.close_detail = Some(detail.clone());\n" +
				"        if was_closing {\n            self.transition(ReadyState::Closed, TransitionCause::ReceiveClose);\n" +
				"            self.emit(SemanticEventKind::Close(detail));\n            return Ok(());\n        }\n" +
				"        self.emit(SemanticEventKind::Close(detail));",
			Note: "the close event is emitted AFTER the transition instead of before",
		},
		{
			// US-013 AC5 "truncation".
			ID: "m013-payload-truncation", Operator: "payload-truncation", File: framing,
			Match:   "payload.extend_from_slice(&data[header.header_len..header.header_len + payload_len]);",
			Replace: "payload.extend_from_slice(&data[header.header_len..header.header_len + payload_len.saturating_sub(1)]);",
			Note:    "every decoded payload loses its last byte",
		},
		{
			// US-014 AC5 "control-interleaving".
			ID: "m014-control-interleave-resets-accounting", Operator: "control-interleave-corruption", File: connection,
			Match:   "Opcode::Ping => {\n                self.emit(SemanticEventKind::Ping {",
			Replace: "Opcode::Ping => {\n                self.message_buffered = 0;\n                self.emit(SemanticEventKind::Ping {",
			Note:    "a ping interleaved into a fragment sequence resets the buffered accounting",
		},
		{
			// US-014 AC5 "UTF-8-boundary".
			ID: "m014-utf8-boundary-lossy", Operator: "utf8-boundary-leniency", File: framing,
			Match: "let text = Charsetfunctions::string_utf8(payload)\n" +
				"                .map_err(|_| TypedProtocolFailure::java_invalid_data(1007))?;",
			Replace: "let text = Charsetfunctions::string_utf8(payload.clone())\n" +
				"                .unwrap_or_else(|_| String::from_utf8_lossy(&payload).into_owned());",
			Note: "the fin-time strict UTF-8 boundary gate degrades to lossy decoding",
		},
		{
			// US-014 AC5 "double-delivery".
			ID: "m014-double-delivery-text", Operator: "double-delivery", File: connection,
			Match:   "ProcessOutcome::Text(text) => self.emit(SemanticEventKind::Text { text }),",
			Replace: "ProcessOutcome::Text(text) => {\n                self.emit(SemanticEventKind::Text { text: text.clone() });\n                self.emit(SemanticEventKind::Text { text });\n            }",
			Note:    "every delivered text message is emitted twice",
		},
		{
			// US-015 AC5 "wrong-opcode".
			ID: "m015-send-ping-wrong-opcode", Operator: "wrong-opcode", File: connection,
			Match:   "self.emit_outbound(OutboundCause::SendPing, true, Opcode::Ping, data.clone())",
			Replace: "self.emit_outbound(OutboundCause::SendPing, true, Opcode::Pong, data.clone())",
			Note:    "send_ping puts a pong on the wire",
		},
		{
			// US-015 AC5 "unwanted-reply" (Q18: the reference model has NO
			// automatic pong inside the core).
			ID: "m015-unwanted-auto-pong", Operator: "unwanted-reply", File: connection,
			Match: "Opcode::Ping => {\n                self.emit(SemanticEventKind::Ping {",
			// Occurrence 1 is the only Ping arm; the inserted reply fires
			// before the ping event, exactly as an accidental auto-pong would.
			Occurrence: 1,
			Replace: "Opcode::Ping => {\n                self.emit_outbound(\n                    OutboundCause::SendPong,\n" +
				"                    true,\n                    Opcode::Pong,\n                    frame.payload.clone(),\n                )?;\n" +
				"                self.emit(SemanticEventKind::Ping {",
			Note: "the core grows an unwanted automatic pong reply",
		},
		{
			// US-015 AC5 "payload-loss" (control plane).
			ID: "m015-ping-payload-loss", Operator: "payload-loss", File: connection,
			Match:   "self.emit(SemanticEventKind::Ping {\n                    data: frame.payload,\n                });",
			Replace: "self.emit(SemanticEventKind::Ping {\n                    data: Vec::new(),\n                });",
			Note:    "the inbound ping payload is dropped from its event",
		},
		{
			// US-016 AC5 "missing-ack".
			ID: "m016-missing-close-ack", Operator: "missing-ack", File: connection,
			Match: "self.emit_outbound(\n            OutboundCause::EchoClose,\n            true,\n            Opcode::Closing,\n" +
				"            CLOSE_CONSTRUCTOR_PAYLOAD.to_vec(),\n        )?;",
			Replace: "",
			Note:    "close-while-open transitions to closing without echoing the ack",
		},
		{
			// US-016 AC5 "premature-closed".
			ID: "m016-premature-closed", Operator: "premature-terminal", File: connection,
			Match:   "self.transition(ReadyState::Closing, TransitionCause::ReceiveClose);\n        Ok(())",
			Replace: "self.transition(ReadyState::Closed, TransitionCause::ReceiveClose);\n        Ok(())",
			Note:    "the echo path lands in Closed instead of Closing (premature terminal)",
		},
		{
			// US-016 AC5 "duplicate-notification".
			ID: "m016-duplicate-close-notification", Operator: "duplicate-notification", File: connection,
			Match:   "self.emit(SemanticEventKind::Close(detail));",
			Replace: "self.emit(SemanticEventKind::Close(detail.clone()));\n        self.emit(SemanticEventKind::Close(detail));",
			Note:    "the remote close notification is emitted twice",
		},
		{
			// US-016 AC5 "stale-fragment".
			ID: "m016-stale-fragment-retained", Operator: "stale-fragment", File: fragment,
			Match:   "let mut assembled = std::mem::take(&mut self.payload);",
			Replace: "let mut assembled = self.payload.clone();",
			Note:    "the accumulator keeps its bytes after delivery (stale fragment leaks into the next message)",
		},
		// --- US-014: fragment accumulator ------------------------------------
		{
			ID: "m014-start-payload-drop", Operator: "payload-loss", File: fragment,
			Match:   "self.opcode = Some(opcode);\n        self.payload = payload;",
			Replace: "self.opcode = Some(opcode);\n        self.payload = payload;\n        self.payload.clear();",
			Note:    "the fragment-start payload is lost",
		},
		{
			ID: "m014-append-drop", Operator: "payload-loss", File: fragment,
			Match:   "self.payload.extend_from_slice(bytes);",
			Replace: "let _ = bytes;",
			Note:    "continuation payloads are lost",
		},
		{
			ID: "m014-finish-tail-drop", Operator: "payload-loss", File: fragment,
			Match:   "assembled.extend_from_slice(tail);",
			Replace: "let _ = tail;",
			Note:    "the fin fragment's payload is lost",
		},
	}
}

// EquivalentAnalyses documents, per mutant id, why a SURVIVOR is
// observably equivalent to the pristine core under the full observable
// vocabulary (not merely under the current judges). A survivor WITHOUT an
// entry here is a genuine coverage gap and fails the campaign exit code.
func EquivalentAnalyses() map[string]string {
	return map[string]string{
		"m016-1005-reason-flip": "PROVEN output-identical by the exhaustive witness " +
			"equivalent_mutant_witnesses_close_chain_redundancy (adversarial_properties.rs): flipping " +
			"rule 2's reason predicate reroutes 1005-with-any-reason through rule 4's `code == 1005` " +
			"arm, which reports the identical Some(1002) — the chain is redundant at 1005 for every " +
			"reason, verified over all 65536 codes x {empty, non-empty} reasons.",
		"m016-range-lower-off-by-one": "PROVEN output-identical by the exhaustive witness " +
			"equivalent_mutant_witnesses_close_chain_redundancy: admitting 1015 into the 1016..2999 " +
			"band moves 1015's rejection from rule 4 (`code == 1015`) to rule 3, but both report " +
			"Some(1002); every other code is untouched. Verified over all 65536 codes x 2 reasons.",
		"m016-send-close-normalize-skip": "PROVEN output-identical by the exhaustive witness " +
			"equivalent_mutant_witnesses_close_chain_redundancy: close_code_rejection(normalize(c), r) " +
			"== close_code_rejection(c, r) for ALL c (normalize changes only 1015 -> 1005, and the " +
			"chain rejects both with the same 1002 for every reason), so no send_close observable can " +
			"change; the Q14 normalization call is Java-faithful site wiring whose pure function is " +
			"separately pinned (m016-normalize-target-swap and m016-normalize-trigger-swap both die).",
		"mprobe-step-counter-fatal-drop": "The fatal-arm step increment mutates state that can never flow " +
			"to an observable: `step` exists only to tag events at emission time, the input that " +
			"poisons the core emits its events BEFORE the failure returns (tagged with the " +
			"pre-increment step), and after poisoning every subsequent input returns StateViolation " +
			"and emits no event or write (pinned by the adversarial_fuzz poisoned-permanence oracle). " +
			"counts() does not expose step. No test, corpus case, or transcript field can distinguish " +
			"the mutant; equivalence holds for the whole observable vocabulary, not just the judges.",
	}
}
