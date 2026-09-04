// Package defectclass makes the CHILD PRD's seeded defect-class list CHECKABLE
// rather than asserted.
//
// IT WAS CALLED ac5class UNTIL 2026-09-04, AND THE NAME WAS THE DEFECT. Two
// documents in this corpus number their stories the same way, so "US-020 AC5"
// names two different clauses:
//
//   - docs/prd-pack/07c-child-prd-us020-us027.md — the CHILD's US-020 AC5, a
//     list of seven seeded defect classes. That is the clause this package
//     implements, and the only one it has ever read: PRDPath below pins the
//     child part and nothing here can reach the other.
//   - docs/prd-pack/03-master-stories-intake-lsp-protocol-labzero.md:13 — the
//     MASTER's US-020 AC5, about a Behavior Delta Ledger classifying every
//     disagreement as preserve / intentionally-correct / unresolved, with
//     unresolved deltas blocking completion. A different subject entirely.
//
// F019 (drafts/self-review/findings/F019-a-criterion-hidden-behind-its-own-namesake.md)
// measured the cost: four passes over the ledger asked "is US-020 AC5 covered?",
// found a Go package carrying the criterion's name, a self-review record and a
// passing gate — all three about the child — and stopped. A package named for a
// criterion number makes the OTHER criterion of that number look implemented.
// So this package is now named for what it does, and the criterion it
// implements is cited by document rather than by number alone. Renaming it
// removes the false hit; it does not implement the master's clause and does not
// claim to. OA-F019-master-us020-ac5, ruled 2026-09-04.
//
// The child's US-020 AC5 (docs/prd-pack/07c-child-prd-us020-us027.md) names
// seven defect classes by hand:
//
//	Seeded Java-quirk emulation, Rust semantic defect, event-order,
//	error-class, close-initiator, consumed-byte, and normalization-collision
//	variants are detected.
//
// cmd/mutctl already applies this discipline to the AC5 clauses of US-013
// through US-016 — its `--- AC5-named defect classes ---` section says each
// entry exists "so the AC5 evidence is class-complete, not merely
// operator-complete". That section is a COMMENT, and a comment cannot fail.
// It was also never applied to US-020's own seven.
//
// This package closes both halves:
//
//  1. The seven class names are PARSED OUT OF THE PRD (ClassesFromPRD), never
//     retyped here, so adding or renaming a class in the PRD fails the
//     register instead of silently widening it.
//  2. Every class binds to at least one SEEDED VARIANT that resolves to an
//     exact literal in the shipped tree, declares the exact normalized
//     differential observation fields it moves, and names the evidence that
//     must kill it. cmd/ac5ctl executes all of that and reads the exit codes.
//
// WHAT "DETECTED" MEANS HERE, AND WHY IT IS NOT ONE THING. US-020's
// observation vocabulary is the `java-websocket-oracle` transcript
// (rust/ws-oracle-harness/src/observe.rs): events[], frames[], transitions[],
// close, counts, final_state and error. A seeded variant is detected when a
// NAMED piece of evidence fires on it. For most classes that evidence is the
// differential itself: the normalized observation moves, at named field
// paths, and [Variant.Discriminates] records exactly which. For the
// normalization-collision class it is deliberately NOT the differential —
// that is the definition of the class — so the variant carries a
// [Collision] record instead, naming the out-of-band witness that proves the
// two behaviours are genuinely different and the judges that stay green.
//
// A variant with no Discriminates and no Collision is a class that no longer
// discriminates and no longer admits it. That combination fails.
package defectclass

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PRDPath is the child PRD part that carries the US-020 acceptance criteria,
// relative to the repository root.
const PRDPath = "docs/prd-pack/07c-child-prd-us020-us027.md"

// Detector names the evidence that must fire on a seeded variant, by test
// name and not merely by suite. Existence of a failing suite is not identity:
// [Detector.MustFail] is the specific test whose failure is the detection.
type Detector struct {
	// Package is the cargo package the detector runs in.
	Package string `json:"package"`
	// Args are the extra `cargo test` arguments (target selection and the
	// exact-name filter). Empty means the whole package.
	Args []string `json:"args,omitempty"`
	// MustFail is the test name that must appear among the failures. A
	// nonzero exit whose failing set does not contain this name is NOT a
	// detection of this class — it is an unrelated kill.
	MustFail string `json:"must_fail"`
	// Why states, in one sentence, what the named test asserts.
	Why string `json:"why"`
}

// Collision records a seeded variant the differential's normalization maps
// onto the SAME observation as the pristine tree — two genuinely different
// behaviours, one normalized observation.
//
// This is not hypothetical. Shipped Java's server closes the TCP connection
// once its close echo has drained and the port did not; the differential read
// parity for weeks because the transcript vocabulary has no transport
// dimension at all. evidence/java/observed-close-divergences.json measured
// the gap at 123 server cases as DIV-02, and the fix landed at d433c21 only
// because a person noticed. A registered collision seed finds it by
// construction: the witness proves the behaviours differ, the differential
// proves the observation does not.
type Collision struct {
	// DivergenceID is the measured divergence this seed reproduces.
	DivergenceID string `json:"divergence_id"`
	// Mechanism says why the normalization cannot see it.
	Mechanism string `json:"mechanism"`
	// Witness is the out-of-band evidence that MUST FAIL with the variant
	// applied and PASS without it. Without this half a collision seed is
	// indistinguishable from an equivalent mutant.
	Witness Detector `json:"witness"`
	// BlindJudges are the judges that must stay GREEN with the variant
	// applied. Their blindness is the collision; a judge that starts firing
	// means the register is stale, not that the gate may relax.
	BlindJudges []string `json:"blind_judges"`
}

// Variant is one seeded defect: a single deterministic exact-literal
// substitution at a named shipped site, in the same shape cmd/mutctl uses.
type Variant struct {
	// Class is the US-020 AC5 class name, verbatim as the PRD writes it.
	Class string `json:"class"`
	// ID is the seed's stable identifier.
	ID string `json:"id"`
	// Operator names the mutation operator.
	Operator string `json:"operator"`
	// File is repository-relative.
	File string `json:"file"`
	// Match is the exact source literal; Occurrence selects the 1-based
	// occurrence so the enumeration is deterministic.
	Match      string `json:"-"`
	Occurrence int    `json:"occurrence,omitempty"`
	// Replace is the substitution.
	Replace string `json:"-"`
	// Note documents what shipped behaviour the seed corrupts.
	Note string `json:"note"`
	// InE1Campaign marks a seed that is also a row of
	// cmd/mutctl.CuratedMutations, so the E1 campaign judges it too. The
	// binding is enforced by TestAC5RegisterCampaignBindingHolds in
	// cmd/mutctl: a variant claiming this must be a row of that table literal
	// for literal, and a variant NOT claiming it must be absent from it, so no
	// seed can inherit campaign evidence the campaign never produced.
	InE1Campaign bool `json:"in_e1_campaign"`
	// Discriminates is the exact set of normalized differential observation
	// field paths the seed moves, measured (never predicted) by
	// `ac5ctl run`. Array indices are collapsed to `[]`. EMPTY means the
	// differential cannot see this seed at all, which is legal only with a
	// Collision record.
	Discriminates []string `json:"discriminates"`
	// Detector is the evidence that must kill the seed.
	Detector Detector `json:"detector"`
	// Collision is set exactly when Discriminates is empty.
	Collision *Collision `json:"collision,omitempty"`
}

// Ledger cites the behavior-delta ledger record a Java-quirk-emulation seed
// contradicts, so the seed is bound to the recorded decision not to preserve
// the quirk rather than to a reviewer's memory of one.
type Ledger struct {
	// Sequence is the ledger record number.
	Sequence int
	// SubjectRef is the record's subject_ref.
	SubjectRef string
}

// LedgerCitations binds each Java-quirk-emulation seed to the ledger record
// that says the quirk must NOT be preserved.
func LedgerCitations() map[string]Ledger {
	return map[string]Ledger{
		"ac5-jq-handshake-unbounded-head": {
			Sequence:   45,
			SubjectRef: "semantic:org.java-websocket.draft6455.server-handshake.limit-total-bytes.hs0046.corrected:provisional-v1",
		},
		"ac5-jq-violation-close-in-core": {
			Sequence:   49,
			SubjectRef: "semantic:org.java-websocket.websocketimpl.protocol-violation-close-reaction:provisional-v1",
		},
	}
}

const (
	framing    = "rust/ws-core/src/framing.rs"
	connection = "rust/ws-core/src/connection.rs"
	httpHead   = "rust/ws-core/src/handshake/http.rs"
	ioLoop     = "rust/ws-testee/src/io_loop.rs"
)

// closeDetailBlock is the send-close detail literal shared by the
// event-order seed's match and replacement (the seed swaps the two adjacent
// events[] emissions around it and changes nothing else).
const closeDetailBlock = "        let detail = CloseDetail {\n" +
	"            code: i32::from(code),\n" +
	"            reason: reason.to_owned(),\n" +
	"            origin: CloseOrigin::Local,\n" +
	"            remote: false,\n" +
	"            handshake_complete: false,\n" +
	"        };\n" +
	"        self.close_detail = Some(detail.clone());\n" +
	"        self.emit(SemanticEventKind::CloseInitiated(detail));\n"

const sendCloseEmit = "        self.emit_outbound(OutboundCause::SendClose, true, Opcode::Closing, payload)?;\n"

// Register is the committed US-020 AC5 class register: one entry per seeded
// variant, every field measured or cited rather than predicted.
//
// Every Discriminates set below was READ from a run of `ac5ctl run` against
// the pristine tree, and the differential vocabulary it is expressed in was
// itself confirmed against the REAL pinned Java oracle: with the Java arm
// recorded from Java-WebSocket 1.6.0 over the same 74 public and 23 probe
// requests, the pristine port differs from live Java on error.detail alone
// (the documented non-semantic diagnostic wording) and on no behavioural
// field. See evidence/ac5-class-completeness/receipt.json.
func Register() []Variant {
	return []Variant{
		{
			Class: "Java-quirk emulation", ID: "ac5-jq-handshake-unbounded-head",
			Operator: "java-quirk-emulation", File: httpHead,
			Match:   "            if self.buffer.len() >= self.limits.max_handshake_bytes {",
			Replace: "            if false && self.buffer.len() >= self.limits.max_handshake_bytes {",
			Note: "the port grows its handshake head without bound, exactly as shipped Java does — " +
				"the ONE Java behaviour ledger record 45 says in words is not emulated " +
				"(\"JAVA_FAITHFUL_PLUS_SAFE: Java's unbounded growth is NOT emulated\")",
			InE1Campaign:  false,
			Discriminates: nil,
			Detector: Detector{
				Package:  "ws-core",
				Args:     []string{"--test", "handshake_server"},
				MustFail: "configured_budgets_refuse_with_the_named_limit",
				Why: "the exact test ledger record 45 names as the pin for the retained budget; " +
					"it asserts the total-bytes refusal the seed removes",
			},
			Collision: &Collision{
				DivergenceID: "AC5-JQ-STRUCTURAL-no-java-vs-rust-signal",
				Mechanism: "A Java-quirk emulation makes the port agree with Java BY CONSTRUCTION, so a " +
					"Java-versus-Rust COMPARISON can never detect one. Measured, not assumed: with this " +
					"seed applied the normalized observation over all 74 public, 23 probe and 49 handshake " +
					"requests is byte-identical to the pristine tree's. Only a higher-ranked oracle can " +
					"see it, which is US-020 AC2's rule (\"agreement between Java and Rust cannot override " +
					"a higher oracle\") stated as a runnable check rather than as prose.",
				Witness: Detector{
					Package:  "ws-core",
					Args:     []string{"--test", "handshake_server"},
					MustFail: "configured_budgets_refuse_with_the_named_limit",
					Why:      "the rank-three independent expectation the ledger binds to this decision",
				},
				BlindJudges: []string{
					"the differential over the 74-case public corpus (measured by ac5ctl run)",
					"the differential over the 23 differential-regression probes (measured by ac5ctl run)",
					"the 49-case handshake exam — measured once and recorded in " +
						"evidence/ac5-class-completeness/java-arm-parity.json, NOT re-measured by " +
						"ac5ctl (its protocol is case_id-keyed and diffregress is request_id-keyed). " +
						"The exam never reaches the configured budget on any of its 49 cases, which " +
						"ledger record 45 states independently.",
				},
			},
		},
		{
			Class: "Java-quirk emulation", ID: "ac5-jq-violation-close-in-core",
			Operator: "java-quirk-emulation", File: connection,
			Match: "                Err(reject) => {\n" +
				"                    let site = (span.start + reject.consumed).saturating_sub(chunk_start) as u64;\n" +
				"                    self.consumed_bytes = self.consumed_bytes.saturating_add(site);\n" +
				"                    return Err(reject.failure);\n" +
				"                }",
			Replace: "                Err(reject) => {\n" +
				"                    let site = (span.start + reject.consumed).saturating_sub(chunk_start) as u64;\n" +
				"                    self.consumed_bytes = self.consumed_bytes.saturating_add(site);\n" +
				"                    if self.state == ReadyState::Open\n" +
				"                        && reject.failure.code == FailureCode::JavaInvalidData\n" +
				"                    {\n" +
				"                        self.emit_outbound(\n" +
				"                            OutboundCause::SendClose,\n" +
				"                            true,\n" +
				"                            Opcode::Closing,\n" +
				"                            CLOSE_CONSTRUCTOR_PAYLOAD.to_vec(),\n" +
				"                        )?;\n" +
				"                        self.transition(ReadyState::Closing, TransitionCause::SendClose);\n" +
				"                    }\n" +
				"                    return Err(reject.failure);\n" +
				"                }",
			Note: "ws_core acquires shipped WebSocketImpl's protocol-violation close reaction, which " +
				"ledger record 49 places in the ADAPTER and forbids in the core because the core is the " +
				"layer the live-Java differential scores. The record carries its own measurement of that " +
				"change — final_state open->closing and counts.frames +1 on 18 named public cases — and " +
				"this seed reproduces it on a STRICT SUBSET of 14 of those 18 (it hooks the translate-loop " +
				"rejection arm alone, not the whole byte path); nothing moved that the record does not name",
			InE1Campaign:  false,
			Discriminates: []string{"counts.frames", "final_state"},
			Detector: Detector{
				Package:  "ws-core",
				MustFail: "family_seed_corpus_anchors",
				Why: "the adversarial fuzz ordering oracle fires with the verbatim message " +
					"\"transition (SendClose) emitted before its close notification\"",
			},
		},
		{
			Class: "Rust semantic defect", ID: "m013-payload-truncation",
			Operator: "payload-truncation", File: framing,
			Match:   "payload.extend_from_slice(&data[header.header_len..header.header_len + payload_len]);",
			Replace: "payload.extend_from_slice(&data[header.header_len..header.header_len + payload_len.saturating_sub(1)]);",
			Note:    "every decoded payload loses its last byte (the existing US-013 AC5 truncation seed)",
			// Already a row of cmd/mutctl.CuratedMutations.
			InE1Campaign: true,
			Discriminates: []string{
				"close", "close.code", "close.reason",
				"counts.buffered_bytes", "counts.frames", "counts.message_buffered_bytes",
				"error",
				"events", "events[].bytes", "events[].code", "events[].data_base64",
				"events[].reason", "events[].text", "events[].utf8_bytes",
				"final_state", "frames", "frames[].payload_base64", "frames[].payload_bytes",
				"initial_state", "outcome", "role", "transitions",
			},
			Detector: Detector{
				Package:  "ws-core",
				MustFail: "control_payload_exactly_125_delivers",
				Why:      "a control payload of exactly 125 bytes must arrive whole",
			},
		},
		{
			Class: "event-order", ID: "ac5-event-order-send-close-pair-swap",
			Operator: "event-order-swap", File: connection,
			Match:   sendCloseEmit + closeDetailBlock,
			Replace: closeDetailBlock + sendCloseEmit,
			Note: "the two ADJACENT events[] entries of a local close swap places: close_initiated is " +
				"recorded before send_close. Nothing else changes — same detail, same frame, same counts",
			InE1Campaign: false,
			Discriminates: []string{
				"events[].code", "events[].handshake_complete", "events[].opcode",
				"events[].origin", "events[].reason", "events[].remote", "events[].type",
			},
			Detector: Detector{
				Package:  "ws-core",
				Args:     []string{"--test", "close_eof"},
				MustFail: "local_close_emits_frame_detail_and_transition",
				Why:      "its assertion message is literally \"derive.go: emitOutbound precedes close_initiated\"",
			},
		},
		{
			Class: "error-class", ID: "ac5-error-class-input-to-buffer",
			Operator: "error-class-swap", File: connection,
			Match:   "return Err(TypedProtocolFailure::protocol(\n                    FailureCode::InputLimitExceeded,\n                ));",
			Replace: "return Err(TypedProtocolFailure::protocol(\n                    FailureCode::BufferLimitExceeded,\n                ));",
			Note: "the max_input_bytes refusal reports the wrong ERROR CLASS " +
				"(BUFFER_LIMIT_EXCEEDED instead of INPUT_LIMIT_EXCEEDED). Both classes carry NO close " +
				"code, so no close code can move and error.code — the class itself — is what does. " +
				"That is the whole difference from the close-code operators the criteria audit found " +
				"standing in for this class: measured, they move error.close_code and never error.code. " +
				"error.detail moves with it because the adapter's free-text diagnostic names the class",
			InE1Campaign:  false,
			Discriminates: []string{"error.code", "error.detail"},
			Detector: Detector{
				Package:  "ws-core",
				Args:     []string{"--test", "core_semantics"},
				MustFail: "input_limit_uses_add_bounded_semantics",
				Why:      "it asserts the typed failure class of an over-budget input chunk",
			},
		},
		{
			Class: "close-initiator", ID: "ac5-close-initiator-remote-to-local",
			Operator: "close-initiator-swap", File: connection,
			Match:   "            origin: CloseOrigin::Remote,\n            remote: true,",
			Replace: "            origin: CloseOrigin::Local,\n            remote: false,",
			Note: "a close frame ARRIVING from the peer is recorded as locally initiated. Code, reason " +
				"and handshake_complete are untouched, so only the two initiator fields can move",
			InE1Campaign: false,
			Discriminates: []string{
				"close.origin", "close.remote", "events[].origin", "events[].remote",
			},
			Detector: Detector{
				Package:  "ws-core",
				Args:     []string{"--test", "close_eof"},
				MustFail: "inbound_close_while_open_echoes_the_constructor_payload",
				Why:      "it pins the remote origin of a peer-initiated close",
			},
		},
		{
			Class: "consumed-byte", ID: "m012-consumed-chunk-drop",
			Operator: "counter-increment-drop", File: connection,
			Match:   "self.consumed_bytes = self.consumed_bytes.saturating_add(chunk_len);",
			Replace: "self.consumed_bytes = self.consumed_bytes.saturating_add(0);",
			Note: "surviving chunks stop counting as consumed. This is the ONE of the three operators " +
				"the audit found standing in for a class that actually discriminates it: measured, it " +
				"moves counts.consumed_bytes and nothing else",
			InE1Campaign:  true,
			Discriminates: []string{"counts.consumed_bytes"},
			Detector: Detector{
				Package:  "ws-core",
				Args:     []string{"--test", "core_semantics"},
				MustFail: "surviving_chunks_emit_input_chunk_and_advance_counts",
				Why:      "it pins the consumed-byte arithmetic of a surviving chunk",
			},
		},
		{
			Class: "normalization-collision", ID: "ac5-collision-server-tcp-close",
			Operator: "normalization-collision", File: ioLoop,
			Match:   "    role == Role::Server && state == ReadyState::Closing\n}",
			Replace: "    let _ = (role, state);\n    false\n}",
			Note: "the port's server stops closing the TCP connection after its close echo — the exact " +
				"wire behaviour shipped Java has and the port lacked until d433c21, measured at 123 " +
				"server cases as DIV-02. Two genuinely different behaviours; ONE normalized observation",
			InE1Campaign:  false,
			Discriminates: nil,
			Detector: Detector{
				Package:  "ws-testee",
				Args:     []string{"--test", "loopback"},
				MustFail: "a_server_closes_the_tcp_connection_once_its_close_echo_has_drained",
				Why: "a real-socket test that reads EOF from the peer end; it is the only evidence in " +
					"the repository that can tell the two behaviours apart",
			},
			Collision: &Collision{
				DivergenceID: "DIV-02-server-leaves-tcp-open",
				Mechanism: "The `java-websocket-oracle` observation vocabulary has NO transport dimension: " +
					"events[], frames[], transitions[], close, counts, final_state and error describe the " +
					"WebSocket connection, never the socket under it. Who hangs up is not a field, so both " +
					"behaviours normalize to the same observation and the differential reads parity. That " +
					"is what happened for real: evidence/java/observed-close-divergences.json had to " +
					"measure DIV-02 out of band, from Autobahn report bytes, because no differential " +
					"case could.",
				Witness: Detector{
					Package:  "ws-testee",
					Args:     []string{"--test", "loopback"},
					MustFail: "a_server_closes_the_tcp_connection_once_its_close_echo_has_drained",
					Why:      "reads EOF (or its absence) from a real peer socket",
				},
				BlindJudges: []string{
					"cargo test -p ws-core (the E1 campaign's judge 1)",
					"java-vs-rust differential over the 74-case public corpus",
					"java-vs-rust differential over the 23 differential-regression probes",
				},
			},
		},
	}
}

// RejectedBindings records, by name, the operators this repository could have
// claimed for a US-020 AC5 class and which MEASUREMENT says do not
// discriminate it. Keeping them here is the point: the gap being closed is
// "an operator exists" standing in for "the class is detected", and the only
// way not to reintroduce it one level up is to write down what was tested and
// rejected.
//
// Every field set below was read from a run against the live pinned Java
// oracle, not predicted.
func RejectedBindings() []Rejection {
	return []Rejection{
		{
			Class: "error-class", Operator: "close-code-swap", MutantID: "m014-orphan-close-code-swap",
			Moves:  []string{"error.close_code"},
			Reason: "it moves the close CODE carried by a JAVA_INVALID_DATA rejection; error.code — the class — never changes. A close code is not an error class.",
		},
		{
			Class: "error-class", Operator: "close-code-swap", MutantID: "m016-eof-code-swap",
			Moves:  []string{"close.code", "events[].code"},
			Reason: "same shape one layer over: the EOF close code moves, the error class does not.",
		},
		{
			Class: "close-initiator", Operator: "close-echo-swap", MutantID: "m016-echo-payload-swap",
			Moves:  []string{"frames[].payload_base64", "frames[].payload_bytes", "frames[].wire_bytes"},
			Reason: "it moves the echoed PAYLOAD. close.origin, close.remote and transitions[].cause — every field that says who initiated — are untouched.",
		},
		{
			Class: "close-initiator", Operator: "close-transition-swap", MutantID: "m016-echo-branch-flip",
			Moves: []string{"counts.frames", "events.length", "final_state", "frames.length",
				"transitions.length", "transitions[].to"},
			Reason: "it moves the transition TARGET and the echo's existence. transitions[].cause, close.origin and close.remote never move, so it discriminates the close transition, not the initiator.",
		},
		{
			Class: "consumed-byte", Operator: "payload-truncation", MutantID: "m013-payload-truncation",
			Moves:  []string{"22 field paths, none of them counts.consumed_bytes"},
			Reason: "the loudest mutant in the table moves almost every observation field and leaves the consumed-byte counter exactly right. Breadth is not identity.",
		},
		{
			Class: "event-order", Operator: "event-order-swap", MutantID: "m013-close-event-order-swap",
			Moves:  []string{},
			Reason: "the existing US-013 AC5 event-order seed moves NOTHING in the differential. It reorders a close EVENT against a TRANSITION, and the normalization projects events[] and transitions[] into separate arrays, so every ordering relation BETWEEN the arrays is erased. It is a second normalization collision, found by this register rather than by a person.",
		},
		{
			Class: "event-order", Operator: "event-order-swap", MutantID: "cand-event-order-outbound-pair-swap",
			Moves:  []string{},
			Reason: "swapping emit_outbound's own two emissions is invisible for the same reason: one lands in frames[], the other in events[]. Only a swap of two ADJACENT events[] entries is observable, which is why the registered seed is the send_close/close_initiated pair.",
		},
	}
}

// Rejection is one measured negative result: an operator that exists and does
// not discriminate the class it was standing in for.
type Rejection struct {
	Class    string   `json:"class"`
	Operator string   `json:"operator"`
	MutantID string   `json:"mutant_id"`
	Moves    []string `json:"moves"`
	Reason   string   `json:"reason"`
}

// ClassesFromPRD parses the seven US-020 AC5 class names out of the PRD
// itself. The register is checked against THIS, never against a retyped copy,
// so a class added to or renamed in the PRD fails the gate.
func ClassesFromPRD(root string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, PRDPath))
	if err != nil {
		return nil, err
	}
	const head = "### US-020"
	body := string(raw)
	start := strings.Index(body, head)
	if start < 0 {
		return nil, fmt.Errorf("%s: no %q heading", PRDPath, head)
	}
	// Stop at the next story so a later story's clause cannot be read.
	rest := body[start+len(head):]
	if next := strings.Index(rest, "\n### "); next >= 0 {
		rest = rest[:next]
	}
	const prefix = "- Seeded "
	const suffix = " variants are detected."
	var clause string
	for _, line := range strings.Split(rest, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, suffix) {
			clause = strings.TrimSuffix(strings.TrimPrefix(line, prefix), suffix)
			break
		}
	}
	if clause == "" {
		return nil, fmt.Errorf("%s: US-020 has no %q...%q clause", PRDPath, prefix, suffix)
	}
	clause = strings.ReplaceAll(clause, ", and ", ", ")
	clause = strings.ReplaceAll(clause, " and ", ", ")
	var classes []string
	for _, part := range strings.Split(clause, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			classes = append(classes, part)
		}
	}
	if len(classes) == 0 {
		return nil, fmt.Errorf("%s: US-020 AC5 clause parsed to no classes", PRDPath)
	}
	return classes, nil
}

// Verify is the static half of the gate: it runs without cargo, without the
// Java oracle and without a network, and it fails when a US-020 AC5 class
// loses its seeded variant, when a variant's site drifts out of the tree, or
// when a variant stops discriminating without registering the collision.
// Returns one problem string per violation.
func Verify(root string) []string {
	return VerifyRegister(root, Register())
}

// VerifyRegister is [Verify] over an explicitly supplied register. It exists
// so the gate's own ability to FAIL is provable: the package tests hand it a
// register with a class dropped, a site drifted and a collision unregistered,
// and assert it says so. A check nobody has watched fail is an assertion.
func VerifyRegister(root string, register []Variant) []string {
	var problems []string
	classes, err := ClassesFromPRD(root)
	if err != nil {
		return []string{fmt.Sprintf("reading the AC5 clause: %v", err)}
	}
	declared := map[string]bool{}
	for _, c := range classes {
		declared[c] = true
	}
	covered := map[string]int{}
	seen := map[string]bool{}
	for _, v := range register {
		if seen[v.ID] {
			problems = append(problems, fmt.Sprintf("%s: duplicate variant id", v.ID))
			continue
		}
		seen[v.ID] = true
		if !declared[v.Class] {
			problems = append(problems, fmt.Sprintf(
				"%s: class %q is not one of the %d classes US-020 AC5 names in %s",
				v.ID, v.Class, len(classes), PRDPath))
		}
		covered[v.Class]++
		if v.Match == v.Replace {
			problems = append(problems, fmt.Sprintf("%s: identity replacement", v.ID))
		}
		if line, err := ResolveSite(root, v); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", v.ID, err))
		} else if line <= 0 {
			problems = append(problems, fmt.Sprintf("%s: resolved to line %d", v.ID, line))
		}
		switch {
		case len(v.Discriminates) == 0 && v.Collision == nil:
			problems = append(problems, fmt.Sprintf(
				"%s (class %q): the differential does not discriminate this seed and no collision is "+
					"registered — a class that no longer discriminates and does not admit it",
				v.ID, v.Class))
		case len(v.Discriminates) > 0 && v.Collision != nil:
			problems = append(problems, fmt.Sprintf(
				"%s (class %q): registers a normalization collision AND discriminating fields %v; "+
					"a collision is exactly the absence of those", v.ID, v.Class, v.Discriminates))
		}
		if v.Collision != nil && strings.TrimSpace(v.Collision.Witness.MustFail) == "" {
			problems = append(problems, fmt.Sprintf(
				"%s: a collision seed without an out-of-band witness cannot be told apart from an "+
					"equivalent mutant", v.ID))
		}
		if strings.TrimSpace(v.Detector.MustFail) == "" {
			problems = append(problems, fmt.Sprintf(
				"%s: no named detector — a failing suite is existence, a failing NAMED test is identity",
				v.ID))
		}
		if !sort.StringsAreSorted(v.Discriminates) {
			problems = append(problems, fmt.Sprintf("%s: Discriminates is not sorted", v.ID))
		}
	}
	for _, c := range classes {
		if covered[c] == 0 {
			problems = append(problems, fmt.Sprintf(
				"US-020 AC5 class %q has NO seeded variant: the class list in %s names it and the "+
					"register does not cover it", c, PRDPath))
		}
	}
	return problems
}

// ResolveSite returns the 1-based line number of the variant's site in the
// shipped tree. A drifted site is a hard error, never a skip: a seed that no
// longer resolves is a class that has quietly lost its variant.
func ResolveSite(root string, v Variant) (int, error) {
	source, err := os.ReadFile(filepath.Join(root, v.File))
	if err != nil {
		return 0, err
	}
	offset, err := OccurrenceOffset(string(source), v.Match, v.Occurrence)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", v.File, err)
	}
	return 1 + strings.Count(string(source[:offset]), "\n"), nil
}

// OccurrenceOffset finds the byte offset of the n-th (1-based) occurrence of
// match in source.
func OccurrenceOffset(source, match string, occurrence int) (int, error) {
	if occurrence < 1 {
		occurrence = 1
	}
	at := 0
	for i := 0; i < occurrence; i++ {
		next := strings.Index(source[at:], match)
		if next < 0 {
			return 0, fmt.Errorf("occurrence %d of %q not found (found %d)",
				occurrence, firstLine(match), i)
		}
		at += next
		if i < occurrence-1 {
			at += len(match)
		}
	}
	return at, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + "..."
	}
	return s
}
